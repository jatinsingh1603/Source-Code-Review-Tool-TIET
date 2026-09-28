# ADR-0007: Pipeline contracts

| | |
|---|---|
| Status | Proposed |
| Date | 2026-09-28 |
| Deciders | Project maintainers |
| Issue | #126 (E04-01) |
| Affects | `docs/ARCHITECTURE.md` section 4 (one pointer sentence); `codekavach.core.pipeline`, `codekavach.core.plugins`, `codekavach.core.store`; invariants I3, I4, I5; every epic that writes a stage (E06 to E33) |

## Context and problem statement

`docs/ARCHITECTURE.md` section 4 defines the `Stage` protocol with exactly four members (`name`, `requires`, `provides`, `run`) and says that `RunContext` carries configuration, the artefact store, the event bus, the cancellation token and the budget. Epic E04 has to refine that section in several ways:

- optional stage metadata;
- how artefacts are named, typed and hashed;
- what happens when a stage fails;
- how stages run concurrently;
- how results are cached;
- how the scan salt is carried.

Every later epic builds stages against these decisions, so they are written down once, here, before thirty issues spread them through the code. The architecture document stays normative; this record refines section 4 without changing a module name or an invariant.

## Decision drivers

- Third-party stages written against section 4 must keep working (entry-point plugins, E04-10).
- Determinism (I5): the same inputs, settings and salt give the same outputs regardless of thread scheduling.
- Fail closed (I4): a failure on the privacy path stops egress instead of degrading silently.
- No exposure through the pipeline itself (I3): failure records, events and caches carry no client code, secrets or salt.
- Offline and local first: threads over processes, no network, a SQLite state store.
- Checkability: each rule has a named test or import contract.

## Considered options

The options per decision are listed with the decision (D1 to D14 below). The general alternative, widening the `Stage` protocol with every new attribute, was rejected in D1.

## Decision outcome

### D1 Protocol is unchanged

`Stage` stays exactly as in section 4. Everything else is optional metadata, read with `getattr` by `describe_stage(stage) -> StageInfo`:

| Attribute | Default |
|---|---|
| `version: str` | `"0"` |
| `category: StageCategory \| None` | `None` |
| `optional_requires: frozenset[str]` | empty |
| `failure_policy` | from the category (D2) |
| `cacheable` | from the category (D2) |
| `salt_dependent` | from the category (D2) |
| `parallel_safe: bool` | `True` |
| `timeout_seconds: int \| None` | `None` |
| `transient_provides: frozenset[str]` | empty |
| `config_sections: tuple[str, ...] \| None` | `None` |
| `plugin_api: int` | `1` |

Rationale: stages from third parties and from older code need only the four members; new behaviour is opt-in. Rejected: widening the Protocol, which would break every stage written against the architecture document.

### D2 Categories and safe defaults

`StageCategory` has one member per default stage name. Each category has a default failure policy, a default `cacheable` flag and a default `salt_dependent` flag (table in E04-02). A stage without a category is treated as the most restrictive case: `FAIL_CLOSED`, not cacheable, salt dependent. A stage may tighten a default, not weaken it.

Rationale: an author who forgets to classify a stage gets the safe behaviour, not the fast one. Rejected: permissive defaults (not cacheable but `DEGRADE`), which would let an unclassified privacy stage fail without locking egress.

### D3 Artefact keys

Keys are lower-case dotted strings. The well-known vocabulary lives in `core/pipeline/keys.py` (E04-03); third parties may add keys. A key provided by several stages is stored as one part per providing stage and read back ordered by part name, so the merge order does not depend on thread scheduling (I5).

Rationale: several analyse stages provide `candidates.raw`, and their merge must be reproducible. Rejected: appending in completion order, which varies with scheduling.

### D4 Typed artefact access

The reader states the expected model: `get(key, Model)`, `get_list(key, Model)` or `get_json(key)`. The stored type tag is compared with the requested model and is not imported. No `pickle`.

Rationale: a tampered or stale cache must not be able to trigger imports or code execution. Rejected: storing a dotted class path and importing it on read.

### D5 Transient artefacts

Objects that cannot be serialised (tree-sitter trees) are held in memory only and declared through `transient_provides`. A stage with transient outputs always runs; it is not served from the cache.

Rationale: parse trees are large, library-specific and not needed after the run. Rejected: pickling them, which conflicts with D4.

### D6 Failure policy

There are three policies:

- `ABORT_SCAN` ends the run as failed.
- `DEGRADE` continues with every stage whose hard requirements are still met.
- `FAIL_CLOSED` continues like `DEGRADE` and also puts the run into egress lockout: no stage of category `PRIVACY` or `LLM`, and no stage without a category, starts afterwards.

Outputs of a failed stage are discarded. Per-candidate fail-closed behaviour (I4) happens inside the privacy stages (E04-20); the stage-level policy is the backstop.

Rationale: a failure on the privacy path must stop egress, while a failed optional engine should not stop the report. Rejected: one global "stop on any error" switch, which makes every engine hiccup fatal, and "log and continue", which violates I4.

### D7 Sanitised failure records

Failure records, events and the scan manifest carry a machine `error_code` and the exception class name only, not `str(exc)`, because exception text can quote client code.

Rationale: exception messages from parsers and engines routinely include source lines. Rejected: redacting `str(exc)`, which is best effort and cannot be proven complete.

### D8 Threading model

Stages run in threads, because the heavy engines are subprocess-bound (ADR-0002). Waves are derived from the dependency graph (E04-12), `scan.jobs` bounds the pool, and a stage that is not `parallel_safe` runs alone. A timed-out thread cannot be killed, so its artefact-store view is revoked (E04-17) and its late writes are rejected.

Rationale: threads share the in-memory store and event bus without serialisation. Rejected: a process pool, which would require pickling contexts (D4) and complicate cancellation.

### D9 Cache key

Stage results are cached under a derivation-style key: `sha256` over

- the prefix `ck-stage-v1`;
- the stage name and version;
- the distribution version;
- the settings fingerprint (E03-39);
- the salt fingerprint, when the stage is salt dependent;
- the digests of all input artefacts.

Rationale: any change that can alter a stage's output changes its key, so stale results are not reused. Rejected: time-based invalidation, which is neither correct nor reproducible.

### D10 Scan salt

The caller supplies the salt; the vault epic (E10) owns its storage. E04 carries it in a wrapper with a redacted `repr`, does not write it to disk, and records only `sha256(b"ck-salt-fp-v1" + salt)[:16]` (E04-06).

Rationale: pseudonyms are only as secret as the salt (I3). Rejected: deriving the salt from the scan id, which is recorded in the manifest.

### D11 Events

Events form a closed vocabulary of frozen classes. Their string fields accept identifier characters only, so an event cannot carry a path, a snippet or free text (E04-05).

Rationale: events reach logs, the CLI and the server; a structural restriction is testable, while a redaction pass is not. Rejected: free-form event dictionaries.

### D12 Resume

Resume re-enters the same scan id with the same settings fingerprint and the same salt fingerprint and relies on the stage cache (D9); non-cacheable stages run again (E04-28).

Rationale: a resume under different settings or a different salt would mix incompatible pseudonyms and findings. Rejected: resuming from a stage index without fingerprint checks.

### D13 Layering

`codekavach.core.pipeline`, `codekavach.core.plugins` and `codekavach.core.store` import, from inside the package, only `codekavach.core.models`, `codekavach.core.log` and `codekavach.config`. The import contract `core-is-bottom-layer` enforces this (E04-30).

Rationale: stages depend on the core, and the core does not depend on stages. Rejected: allowing the orchestrator to import concrete stages, which would make plugins second-class.

### D14 Migrations directory

Alembic scripts live in `src/codekavach/core/store/migrations/` as a data directory without `__init__.py`. The package tree of section 3 and the layout test of E01 are therefore unchanged, and no migration script is imported outside an Alembic run (E04-26). This is the project's single Alembic migration tree: server mode (E32) extends it with PostgreSQL support and additional tables and does not start a second tree or a parallel database.

Rationale: one schema history for local and server mode. Rejected: a migrations Python package, which the layout test would have to special-case.

## Stage and artefact-key contract

Reference contract for the default pipeline. Keys are the constants of E04-03. Owning epics may refine their row through a follow-up ADR.

| Stage | Category | requires | optional_requires | provides |
|---|---|---|---|---|
| `ingest` | INGEST | `scan.target` | | `files`, `languages` |
| `parse` | PARSE | `files`, `languages` | | `ast` (transient), `symbols`, `callgraph` |
| `analyse-*` | ANALYSE | `files` plus what the analysis needs | | `candidates.raw` (one part per stage) |
| `aggregate` | AGGREGATE | `candidates.raw` | | `candidates` |
| `privacy-prepare` | PRIVACY | `candidates`, `files` | `ast`, `symbols`, `callgraph` | `payloads.sanitised` |
| `llm-review` | LLM | `payloads.sanitised` | | `verdicts.raw` |
| `restore` | RESTORE | `verdicts.raw` | | `verdicts.restored` |
| `rate` | RATE | `candidates` | `verdicts.restored` | `findings`, `scan.summary` |
| `report` | REPORT | `findings` | `scan.summary` | `report.outputs` |
| `sync` | SYNC | `findings` | | `sync.result` |

The optional requirement on `verdicts.restored` is what lets a scan finish from deterministic evidence when the LLM path is disabled, skipped or locked out (D6).

### Consequences (positive, negative, neutral)

- Positive: every E04 issue and every stage author works from one reference, and the safe behaviour is the default for unclassified stages.
- Positive: determinism and failure handling are properties of the orchestrator, not of each stage.
- Negative: optional metadata read with `getattr` is invisible to type checkers, so `describe_stage` is the single place that validates it (E04-02).
- Neutral: the reference table describes the default pipeline only; plugins add rows without changing this record.

### Compliance: how the decision is enforced (tests, contracts, CI checks)

| Decision | Issue that implements or tests it |
|---|---|
| D1, D2 | #127 (E04-02): `describe_stage` and the category defaults table |
| D3 | #128 (E04-03) key vocabulary; #129 (E04-04) ordered parts; #144 (E04-19) deterministic concurrent merge |
| D4 | #129 (E04-04) typed access; #134 (E04-09) on-disk store without `pickle` |
| D5 | #129 (E04-04) transient keys; #146 (E04-21) transient outputs bypass the cache |
| D6 | #140 (E04-15) failure policy and egress lockout; #145 (E04-20) per-item failures |
| D7 | #140 (E04-15) sanitised failure records; #149 (E04-24) manifest |
| D8 | #137 (E04-12) waves; #142 (E04-17) revocable store view; #143 (E04-18) timeouts; #144 (E04-19) thread pool |
| D9 | #146 (E04-21) derivation-keyed stage cache; E03-39 settings fingerprint |
| D10 | #131 (E04-06) `ScanSalt` with redacted `repr` and fingerprint |
| D11 | #130 (E04-05) closed event vocabulary |
| D12 | #153 (E04-28) checkpoints and resume |
| D13 | #155 (E04-30) import contract `core-is-bottom-layer` |
| D14 | #151 (E04-26) Alembic migrations directory and drift check |

## Privacy impact (invariants I1 to I6: strengthened, unchanged, or weakened and why that is acceptable)

- I3 is strengthened at pipeline level: the salt is not written to disk and only its fingerprint is recorded (D10); failure records carry no exception text (D7); events cannot carry free text (D11).
- I4 is strengthened: a failed privacy-path stage locks egress for the rest of the run (D6), and unclassified stages default to the fail-closed policy (D2).
- I5 is strengthened: multi-provider artefacts merge in part-name order (D3), and caching and resume are keyed by the settings and salt fingerprints (D9, D12).
- I1, I2 and I6 are unchanged: this record adds no network path, does not change what the LLM layer accepts, and does not change payload construction.

No invariant is weakened. The mechanisms block the listed exposures only as far as their named tests check; they do not replace review of new stages.

## Implementation notes (optional; the only section that may grow after acceptance)

## Links

- `docs/ARCHITECTURE.md` sections 3, 4 and 6.3 (I3, I4, I5).
- `docs/PLAN.md` section 4 (principles 1, 2 and 7).
- ADR-0002 (external engines as subprocesses; reserved), ADR-0003 (single egress), ADR-0006 (configuration layering, secrets and trust).
- Epic #125 (E04).
