# Pipeline reference

How a scan runs: the contracts of a stage, the artefact store that connects stages, the events a run publishes, what happens when a stage fails, how results are cached and resumed, and what is left on disk. This page is the reference; [Writing a stage](writing-a-stage.md) is the guide for authors, and [ADR-0007](../adr/0007-pipeline-contracts.md) records why the rules are what they are. Related pages: [Checkpoints and resuming a scan](resume.md) and [Local database](database.md).

Every `python test` block on this page is executed by `tests/docs/test_pipeline_docs.py`, and the tables of events, stage metadata and categories, manifest and checkpoint fields, settings and error types are compared with the code by the same module, so they cannot drift from it unnoticed.

## Overview

A scan is an ordered list of **stages**. A stage declares which artefact keys it reads (`requires`) and writes (`provides`); the orchestrator derives the order from those declarations, and nothing else.

```text
 plugins                 plan                         run
 +-----------+   +-------------------+   +--------------------------------------------+
 | Stage x N |-->| resolve_order     |-->| wave 1:  ingest                            |
 | StageInfo |   | resolve_waves     |   | wave 2:  parse                             |
 +-----------+   | (requires/provides|   | wave 3:  analyse-rules | analyse-taint ... |  up to scan.jobs
   discovery +   |  and scan.target) |   | wave 4:  aggregate ... rate ... report     |  at once
   allow-list    +-------------------+   +--------------------------------------------+
                                           per stage: scoped store + RunContext
                                           -> run() -> outputs checked -> StageRun + events
```

- Plugins are discovered through entry points and loaded lazily. The `[plugins]` allow-list and disable-list are applied before anything is imported (`codekavach.core.plugins.policy`).
- `build_plan` or `plan_from_stages` turns stages into a `RunPlan`: the resolved order, the waves (stages of one wave do not depend on each other) and the stages that were left out, with the reason.
- `Orchestrator.run` executes a plan. `run_scan` (`codekavach.core.pipeline.runner`) wraps it with the state directory, the stage cache, the manifest, the checkpoint and the local database.
- A scan's stage names, artefact keys and the order of the default pipeline are: `ingest`, `parse`, `analyse`, `aggregate`, `privacy-prepare`, `llm-review`, `restore`, `rate`, `report`, `sync`.

## The Stage protocol and its metadata

A stage is any object with four members:

| Member | Type | Meaning |
|--------|------|---------|
| `name` | `str` | Matches `^[a-z][a-z0-9-]{0,47}$`. |
| `requires` | `frozenset[str]` | Artefact keys the stage reads. A missing one means the stage is skipped. |
| `provides` | `frozenset[str]` | Artefact keys the stage writes; at least one. |
| `run(ctx)` | method | Reads `requires` from `ctx.artefacts`, writes `provides`. |

Everything else is optional and read by `describe_stage`, which validates the declaration, applies the category defaults and returns a `StageInfo`:

| Attribute | Default | Meaning |
|-----------|---------|---------|
| `name` | required | The stage name. |
| `requires` | required | Hard requirements. |
| `provides` | required | Outputs. |
| `version` | `"0"` | 1 to 32 characters of `[A-Za-z0-9._-]`; part of the cache key, so change it whenever the output can change. |
| `category` | `None` | A `StageCategory`; selects the defaults below. Without one the stage is fail-closed, not cacheable and salt dependent. |
| `optional_requires` | empty | Keys read when present; their absence does not skip the stage. |
| `failure_policy` | by category | `abort_scan`, `fail_closed` or `degrade` (see [Failure policy](#failure-policy)). |
| `cacheable` | by category | Whether the stage cache may serve its outputs. A stage with transient outputs is not cacheable (`describe_stage`). |
| `salt_dependent` | by category | Whether the output depends on the scan salt; it then gets a salt-separated cache and memo key space. |
| `parallel_safe` | `True` | `False` gives the stage a wave of its own. |
| `timeout_seconds` | `None` | A positive time limit of the stage (see [Timeouts](#timeouts-and-cancellation)). |
| `transient_provides` | empty | Provided keys that stay in memory (a parse tree); a subset of `provides`. |
| `config_sections` | `None` | Settings sections that influence the output; they are fingerprinted into the stage cache key. `None` means the default sections. |
| `plugin_api` | `1` | The plugin API version the stage targets; another value is refused. |
| `origin` | `None` | Set by the registry to `<distribution>==<version>`; it is part of the cache key. |

The defaults by category (`CATEGORY_DEFAULTS`):

| Category | Failure policy | Cacheable | Salt dependent |
|----------|----------------|-----------|----------------|
| `ingest` | `abort_scan` | no | no |
| `parse` | `degrade` | yes | no |
| `analyse` | `degrade` | yes | no |
| `aggregate` | `abort_scan` | yes | no |
| `privacy-prepare` | `fail_closed` | no | yes |
| `llm-review` | `fail_closed` | no | yes |
| `restore` | `fail_closed` | no | yes |
| `rate` | `degrade` | yes | no |
| `report` | `degrade` | no | no |
| `sync` | `degrade` | no | no |
| (none) | `fail_closed` | no | yes |

A privacy, LLM, restore or uncategorised stage cannot declare its way out of its defaults: a weaker `failure_policy`, `cacheable = True` or `salt_dependent = False` raises `StageDeclarationError` (invariants I4 and I5). `ingest` and `sync` cannot be cacheable either.

```python test
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from codekavach.core.pipeline.errors import StageDeclarationError


class Probe:
    name = "analyse-probe"
    requires = frozenset({"files"})
    provides = frozenset({"candidates.raw"})
    category = StageCategory.ANALYSE
    version = "2"

    def run(self, ctx):
        pass


info = describe_stage(Probe(), origin="ck-probe==1.0")
assert info.failure_policy is FailurePolicy.DEGRADE
assert info.cacheable and not info.salt_dependent
assert info.origin == "ck-probe==1.0"


class TooLax(Probe):
    name = "privacy-probe"
    category = StageCategory.PRIVACY
    cacheable = True  # a privacy stage may not be cached


try:
    describe_stage(TooLax())
except StageDeclarationError as error:
    assert "cacheable" in error.problem
else:
    raise AssertionError("a privacy stage must not be cacheable")
```

## Artefact keys

Stages are wired together by key. A key matches `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$` and has at most 64 characters. The vocabulary is open; these are the keys that the default pipeline uses (the constants are in `codekavach.core.pipeline.keys`):

| Key | Produced by | Notes |
|-----|-------------|-------|
| `scan.target` | the runner | `{"target": ...}`; the initial key. |
| `files` | `ingest` | Raw code. |
| `languages` | `ingest` | |
| `ast` | `parse` | Transient; raw code. |
| `symbols` | `parse` | Raw code. |
| `callgraph` | `parse` | Raw code. |
| `candidates.raw` | `analyse-*` | Multi-provider; raw code. |
| `candidates` | `aggregate` | Raw code. |
| `payloads.sanitised` | `privacy-prepare` | The only input of an LLM stage. |
| `verdicts.raw` | `llm-review` | In pseudonym space. |
| `verdicts.restored` | `restore` | |
| `findings` | `rate` | |
| `scan.summary` | `rate` | |
| `report.outputs` | `report` | |
| `sync.result` | `sync` | |
| `scan.item_failures` | the orchestrator | Written by the orchestrator only; consumers use `optional_requires`. |
| `scan.manifest` | the orchestrator | |
| `scan.record` | the runner | The final `Scan`. |

For a single-provider key at most one stage of a plan may provide it (`DuplicateProviderError`). A **multi-provider** key, such as `candidates.raw`, collects one *part* per provider; a consumer reads the parts in part-name order. A stage that requires an LLM payload requires `payloads.sanitised`, not a raw-code key, and the plan builder refuses an LLM stage that reads raw code (pipeline-level support for I2).

## The artefact store

Stages exchange data only through `ctx.artefacts`. What a store offers:

| Method | Meaning |
|--------|---------|
| `put(key, value, *, persist=True)` | Store a value under a single-provider key; the last write wins. `persist=False` keeps an object in memory only. |
| `put_part(key, part, value)` | Store one provider's part of a multi-provider key. |
| `get(key, model)`, `get_list(key, item)`, `get_json(key)` | Read a model, a list of one model class, or a JSON value. |
| `get_object(key)` | Read a transient object. |
| `get_parts(key, item)` | Every part of a multi-provider key, in part-name order. |
| `has(key)`, `ref(key)`, `keys()` | Presence, the reference (digest and size) and the keys that hold a value. |
| `bind`, `bind_part`, `discard` | Used by the orchestrator for cache hits and clean-up. |

A persisted value is a Pydantic model, a list of one model class, or a JSON value, stored as an envelope in canonical JSON (sorted keys, compact separators), so equal values give equal bytes and equal SHA-256 digests on every platform. Reading compares the stored type tag with the requested model, does not import or evaluate anything, and reports an error that names the key and the type but not the value. An object that carries the `__ck_never_persist__` marker (the scan salt, vault material) is refused by every `put` (I3), persisted or not; `tests/unit/core/store/test_base.py` covers it.

A stage does not see the store itself but a **scoped view**: reads and writes of an undeclared key raise `UndeclaredAccessError` (the stage fails with the code `undeclared_access`), and the view is revoked when the stage ends, so a thread that outlives its stage cannot write. The scoped view is a guard against mistakes, not a security boundary.

`InMemoryArtefactStore` keeps everything in the process. `OnDiskArtefactStore` (the default of `run_scan`) writes content-addressed blobs under `cache/blobs` and, for every scan, bindings from keys to blobs under `scans/<scan_id>/index`; every read recomputes the digest of the blob and compares it with the binding. That detects corruption and casual tampering; it is not an integrity control against someone who can rewrite both files.

```python test
from pydantic import BaseModel

from codekavach.core.store.base import ArtefactMissingError
from codekavach.core.store.memory import InMemoryArtefactStore


class Row(BaseModel):
    path: str
    line: int


store = InMemoryArtefactStore()
store.put("scan.target", {"target": "/work/repo"})
store.put_part("candidates.raw", "analyse-a", [Row(path="a.py", line=3)])
store.put_part("candidates.raw", "analyse-b", [Row(path="b.py", line=9)])

assert store.get_json("scan.target") == {"target": "/work/repo"}
parts = store.get_parts("candidates.raw", Row)
assert list(parts) == ["analyse-a", "analyse-b"]  # part-name order
assert parts["analyse-b"][0].line == 9

try:
    store.get("scan.target", Row)  # a JSON value is not a Row
except Exception as error:
    assert type(error).__name__ == "ArtefactTypeError"
else:
    raise AssertionError("a type mismatch must be reported")

try:
    store.get_json("nothing.here")
except ArtefactMissingError:
    pass
```

## Events

The orchestrator publishes events to the bus of the run. Events carry codes, counts, identifiers and durations; a field is a token (`[A-Za-z0-9_.:-]`, 1 to 64 characters), a non-negative integer, a timezone-aware time or a flat tuple of those. Construction rejects a value that is not a token or a number, which excludes paths, code snippets and exception messages; it does not recognise an identifier taken from client code, so a stage must not put one into an event (see the guide).

Every event has `scan_id`, `at` and `seq`; the bus numbers events 1, 2, 3, ... in publication order. The fields below are the ones that each kind adds:

| Event | `kind` | Fields |
|-------|--------|--------|
| `ScanStarted` | `scan.started` | `stage_count` |
| `PlanResolved` | `plan.resolved` | `stages`, `wave_sizes` |
| `StageStarted` | `stage.started` | `stage`, `index`, `total` |
| `StageProgress` | `stage.progress` | `stage`, `current`, `total`, `unit` |
| `StageFinished` | `stage.finished` | `stage`, `outcome`, `duration_ms`, `items_in`, `items_out` |
| `StageFailed` | `stage.failed` | `stage`, `policy`, `error_code`, `error_type`, `duration_ms` |
| `StageSkipped` | `stage.skipped` | `stage`, `reason_code`, `blocked_by` |
| `ItemFailed` | `item.failed` | `stage`, `item_id`, `error_code` |
| `WarningRaised` | `warning` | `stage`, `code` |
| `ScanCancelled` | `scan.cancelled` | `stages_completed` |
| `ScanFinished` | `scan.finished` | `status`, `duration_ms`, `findings_total` |

`InMemoryEventBus` delivers synchronously in subscription order; a handler that raises is logged by exception class and skipped, so a faulty subscriber cannot break a scan. `NullEventBus` drops every event.

```python test
from datetime import UTC, datetime

from codekavach.core.pipeline.events import (
    EVENT_TYPES,
    InMemoryEventBus,
    StageProgress,
)

bus = InMemoryEventBus()
seen = []
bus.subscribe(seen.append)
bus.subscribe(lambda event: 1 / 0)  # a failing handler is skipped

for current in (1, 2):
    bus.publish(StageProgress(scan_id="scan_0001", stage="parse", current=current, unit="files"))

assert [event.seq for event in seen] == [1, 2]
assert seen[0].to_dict()["event"] == "stage.progress"
assert "stage.progress" in EVENT_TYPES
assert seen[0].at.tzinfo is not None and seen[0].at <= datetime.now(UTC)

try:
    StageProgress(scan_id="scan_0001", stage="src/secret/path.py", current=1, unit="files")
except ValueError:
    pass  # a path is not a token
else:
    raise AssertionError("an event field must be a token")
```

## Failure policy

After a stage fails, its outputs are discarded first (for a multi-provider key, only its own part), so nothing half-prepared can be consumed. Then its `failure_policy` decides:

| Policy | What happens next |
|--------|-------------------|
| `abort_scan` | The run ends as `failed`; every later stage is skipped with `scan_aborted`. |
| `degrade` | The run continues with every stage whose hard requirements are still met; the scan ends `completed_with_errors`. |
| `fail_closed` | As `degrade`, and egress is locked for the rest of the run: no privacy, LLM or uncategorised stage starts (I4). |

What the scenarios look like in a run:

| Scenario | Stage outcome and code | Effect on the run |
|----------|------------------------|-------------------|
| A stage raises an exception | `failed`, `stage_exception` | Its policy applies. Only the exception class name is recorded; the message is at DEBUG only. |
| A stage returns without writing a declared output | `failed`, `missing_provides` | As above. |
| A stage reads or writes an undeclared key | `failed`, `undeclared_access` | As above. |
| A stage exceeds its time limit | `timed_out`, `timeout` | The token is cancelled, the view is revoked and the thread is abandoned; the policy applies. |
| A hard requirement is missing | `skipped`, `dependency_missing` | Nothing provides the key and no stage failed. |
| A provider of a requirement failed or was skipped | `skipped`, `dependency_failed` | `blocked_by` names the provider. |
| Egress is locked | `skipped`, `egress_locked` | Privacy, LLM and uncategorised stages; `blocked_by` names the stage that locked it. |
| The scan was aborted | `skipped`, `scan_aborted` | `blocked_by` names the stage that aborted. |
| The user cancels | `cancelled` | Completed stages are kept; the scan ends `cancelled`. |

Locking out the privacy stages as well is deliberate: once one of them has failed, nothing is sent, so preparing more payloads would create material that goes unused. Deterministic stages keep running, so the audit still reports findings from deterministic evidence.

A problem with one **item** (a file, a candidate) is not a stage failure. `ctx.fail_item(item_id, error_code)` records it in a uniform, code-only form, publishes `ItemFailed` and stores it under `scan.item_failures`; `guard_item` wraps the work on one item. `item_id` is an entity id (`cand_...`), not a path, a symbol name or a message, and a rejected value is not echoed.

## Timeouts and cancellation

The effective time limit of a stage is the first of these that applies, capped by what is left of the scan's own limit (`scan.timeout_seconds`):

1. `scan.stage_timeouts[<stage name>]`;
2. `scan.stage_timeouts[<category>]`, for example `analyse`;
3. the `timeout_seconds` the stage declares;
4. `scan.stage_timeout_seconds`.

Python cannot stop a thread, so a stage runs in a dedicated daemon thread and the orchestrator waits with a deadline, in slices of 0.2 s so that Ctrl-C is not delayed. On expiry the stage's token is cancelled with the reason `timeout`, its store view is revoked and the thread is abandoned; the run goes on. A stage that ignores cancellation keeps a thread busy but cannot change results.

Cancellation is cooperative. A stage:

- calls `ctx.check_cancelled()` at least once per unit of work (a file, a candidate); it raises `ScanCancelledError` when the scan was cancelled or its wall-clock budget is used up;
- passes `ctx.remaining_seconds()` to every subprocess or network timeout;
- terminates child processes when `ScanCancelledError` is raised.

With `handle_sigint=True`, the first SIGINT or SIGTERM cancels the scan gracefully (status `cancelled`, manifest and checkpoint written, resumable) and a second one exits the process with status 130.

## Concurrency and determinism

The stages of one wave do not depend on each other, so up to `scan.jobs` of them run at once (`0` means the number of CPUs, at most 32). A stage with `parallel_safe = False` gets a wave of its own.

Results do not depend on scheduling: skip decisions use the state at the start of the wave, failure policies are applied after the wave has settled, in plan order, and stage runs are reported in plan order. A stage keeps that property when it sorts what it stores, uses no wall-clock time or randomness in its results and reads no environment variable.

```python test
from codekavach.core.pipeline.graph import build_graph, resolve_order, resolve_waves
from codekavach.core.pipeline.stage import StageCategory, describe_stage


def stage(name, requires, provides, category):
    return type(
        "S",
        (),
        {
            "name": name,
            "requires": frozenset(requires),
            "provides": frozenset(provides),
            "category": category,
            "run": lambda self, ctx: None,
        },
    )()


infos = [
    describe_stage(stage("ingest", {"scan.target"}, {"files"}, StageCategory.INGEST)),
    describe_stage(stage("analyse-a", {"files"}, {"candidates.raw"}, StageCategory.ANALYSE)),
    describe_stage(stage("analyse-b", {"files"}, {"candidates.raw"}, StageCategory.ANALYSE)),
    describe_stage(stage("aggregate", {"candidates.raw"}, {"candidates"}, StageCategory.AGGREGATE)),
]
graph = build_graph(infos, initial_keys=("scan.target",))
assert resolve_order(graph)[0] == "ingest"
assert resolve_order(graph)[-1] == "aggregate"
assert [len(wave) for wave in resolve_waves(graph)] == [1, 2, 1]  # the two analysers run together
```

## Caches

### The stage cache

Before a cacheable stage runs, the orchestrator computes its stage key: SHA-256 of canonical JSON of the stage name, version and origin, the settings fingerprint of its `config_sections`, the scan salt's fingerprint when the stage is salt dependent, and the digest of every declared input. On a hit the recorded outputs are bound into the current scan and the stage is not called; on a miss it runs and a record is written under `cache/stages`. A corrupt record, or one whose blobs are gone, is a miss. `refresh` names stages or groups that run anyway, and `use_cache=False` (or `scan.cache = false`) turns the cache off.

A stale `candidates` artefact would hide findings, so a cacheable stage meets three conditions:

1. it reads client data only through its declared artefacts and the files listed in `files`, whose hashes are inside that artefact;
2. its `version` is bumped whenever its logic changes;
3. it does not depend on wall-clock time, randomness or environment variables.

Only `parse`, `analyse`, `aggregate` and `rate` stages are cacheable by default. A transient input (a parse tree) has no digest; the key of the stage that produced it stands in, and when that stage has no key the consumer is not cacheable in that run.

### The item memo

The stage cache is all or nothing: one edited file changes the digest of `files` and every downstream stage recomputes. `ctx.memo` gives a stage reuse at the level of one item, usually a file:

```python test
import tempfile
from pathlib import Path

from pydantic import BaseModel

from codekavach.core.pipeline.memo import DiskItemMemo, MemoStats, memo_key
from codekavach.core.store.layout import StateLayout


class Symbols(BaseModel):
    names: list[str]


layout = StateLayout(Path(tempfile.mkdtemp()) / ".codekavach")
memo = DiskItemMemo(layout)
key = memo_key("content-sha256", "python", "grammar-1")  # everything the result depends on
calls = []


def extract():
    calls.append(1)
    return Symbols(names=["main"])


first = memo.get_or_compute("parse.symbols.v1", key, extract, Symbols)
second = memo.get_or_compute("parse.symbols.v1", key, extract, Symbols)
assert first == second and len(calls) == 1
assert memo.stats() == MemoStats(hits=1, misses=1, errors=0)
```

The key must cover everything the computation reads (the content hash, the language, the tool or grammar version and any setting that changes the result); the namespace ends in a version segment that the stage bumps when the computation changes. A truncated, corrupt or differently typed entry is a counted miss and is overwritten; a failed write does not fail the stage (`tests/unit/core/pipeline/test_memo.py`). Salt-dependent stages get a salt-separated key space. The totals appear in `PipelineResult.memo_hits` and `memo_misses` and in the manifest.

## The state directory

Everything below the state directory (`.codekavach/` by default) can contain client code in the clear. Directories are created `0o700` and files `0o600` (POSIX), every caller-supplied path component is validated, writes are atomic through a temporary file, and the directory ignores itself in git.

```text
<state_dir>/
  .gitignore                                "*"
  cache/blobs/<aa>/<sha256>                 content-addressed artefact blobs
  cache/stages/<aa>/<stage_key>.json        stage cache records
  cache/items/<namespace>/<aa>/<key>.json  per-item memo entries
  scans/<scan_id>/index/<key>.json          key -> blob bindings of one scan
  scans/<scan_id>/manifest.json
  scans/<scan_id>/config-snapshot.json
  scans/<scan_id>/checkpoint.json
  codekavach.db                             the local database
```

The cache grows because the store does not overwrite. After a scan, `run_scan` prunes it with `CacheAdmin` (`codekavach.core.store.admin`): temporary files older than an hour are deleted, the blobs referenced by the `scan.cache_keep_scans` newest scans are protected, older scan records are deleted, and when blobs and memo entries exceed `scan.cache_max_size_mb` the least recently used unprotected ones are deleted until 90 per cent of the budget remains. Pruning is best effort and does not fail a scan (`tests/integration/core/test_cache_prune.py`). Deleting is `unlink`, not secure erasure.

## Manifest and checkpoint

Every scan, failed and cancelled ones included, leaves `scans/<scan_id>/manifest.json`. It is provenance metadata designed to travel, so it holds identifiers, versions, codes, counts and durations only: no paths, no host or user names, no environment variables, no exception messages, no settings values, and only a one-way fingerprint of the salt. The scan target is deliberately absent. Its fields:

| Field | Meaning |
|-------|---------|
| `schema_version` | `1`. |
| `scan_id`, `status`, `started_at`, `finished_at`, `duration_ms` | Identity and timing. |
| `codekavach_version`, `python_version`, `python_implementation`, `os`, `machine` | The environment. |
| `settings_fingerprint`, `profile`, `config_snapshot` | The configuration of the scan, by fingerprint. |
| `salt_fingerprint` | A 16-hex-character one-way fingerprint of the salt. |
| `consent_source` | `none`, `user-file`, `flag` or `env`. |
| `order`, `waves`, `excluded` | The plan and the stages left out, with the reason code. |
| `stages` | One entry per stage as it ran: outcome, duration, codes, items in and out, stage key, tool versions. |
| `plugins` | Every discovered entry point with its status. |
| `counters` | Cache and memo hits and misses, item failures, abandoned threads, `egress_locked` and `resumed_from_checkpoint`. |

While a scan runs, the runner keeps `checkpoint.json` up to date after every stage, so a killed process can be resumed too. It holds identifiers, fingerprints, digests and stage names only:

| Field | Meaning |
|-------|---------|
| `v` | `1`. |
| `scan_id`, `status`, `updated_at` | Identity and state (`running`, `cancelled`, `failed`, `completed` or `completed_with_errors`). |
| `codekavach_version`, `settings_fingerprint`, `salt_fingerprint` | What a resume must match. |
| `target_digest` | SHA-256 of the target string, because a path can contain a user or client name. |
| `order`, `completed` | The plan and the stages that ended, with outcome and stage key. |

## Resume

Resuming runs the same scan again under the same identity and lets the stage cache skip what is done: `ingest` and stages with transient outputs run again, completed cacheable stages are cache hits, and privacy, LLM and restore stages always run again. The version, the settings, the salt and the target are verified to be the same, so the payloads are byte-identical to the first attempt (I5). Until the LLM response cache exists, a resumed scan may send the same payloads again. [Checkpoints and resuming a scan](resume.md) has the details and the command line.

## Settings that belong to the pipeline

| Key | Default | Range | Meaning |
|-----|---------|-------|---------|
| `scan.stage_timeout_seconds` | `1800` | 10 to 86400 | Default time limit of one stage, in seconds. |
| `scan.stage_timeouts` | `{}` | each value 10 to 86400 | Time limits per stage name or per category that override the default. |
| `scan.cache_max_size_mb` | `2048` | 64 to 1048576 | Size budget of the cache, in megabytes, used when pruning. |
| `scan.cache_keep_scans` | `5` | 1 to 1000 | The number of newest scans whose records and blobs survive pruning. |
| `plugins.allow_distributions` | `[]` | | Distributions whose plugins may load; empty allows all, and `codekavach` itself is always allowed. Names are compared after PEP 503 normalisation. |
| `plugins.disable` | `[]` | | Plugins to disable, written `kind:name`, for example `engine:semgrep`. The privacy and restore stages cannot be disabled; set `llm.enabled = false` instead. |

`scan.jobs`, `scan.timeout_seconds` and `scan.cache` also act on the pipeline; every key is in the [configuration reference](../configuration/reference.md). The two `plugins` keys are restricted: an untrusted project file cannot set them.

## Error types

| Exception | Raised when |
|-----------|-------------|
| `PipelineError` | The base class of the errors below. |
| `StageDeclarationError` | A stage's declaration breaks the protocol or a no-weakening rule. |
| `GraphError` | The base class of the three graph errors. |
| `DuplicateStageError` | Two stages share a name. |
| `DuplicateProviderError` | A single-provider key has more than one provider. |
| `UnsatisfiedRequirementError` | A stage requires a key that nothing provides. |
| `StageCycleError` | Stages depend on each other in a cycle. |
| `PersistenceError` | The local database could not record the scan; the artefacts and the manifest are on disk. |
| `ScanCancelledError` | The scan was cancelled or its wall-clock budget ran out. |
| `ResumeMismatchError` | A scan cannot be resumed; `field` names the check that failed. |
| `StateLayoutError` | A state path is invalid, escapes the state directory or is unsafe. |
| `PlanError` | The plan cannot be built, or a `refresh` selector matches no stage. |
| `BudgetExceededError` | Charging a scan budget (requests, tokens, cost) would exceed its limit. |
| `DatabaseTooNewError` | The local database was migrated by a newer CodeKavach; nothing was changed. |

## Known limits

- Plugin code is trusted code and is not sandboxed. The allow-list narrows which installed code runs; it does not constrain what an allowed plugin does.
- The scoped store is a guard against mistakes, not a security boundary.
- A resumed scan may send identical payloads again until the LLM response cache exists.
- Pruning deletes with `unlink`; pruned client data may remain recoverable from the disk until its blocks are reused.
- The integrity checks of the store detect corruption and casual tampering, not a determined local attacker.
- Another process that prunes the same state directory can remove blobs a running scan still needs; a scan keeps its bindings only while its directory is among the newest, and a stage that then reads a removed blob fails under the normal policy. There is no cross-process lock.
