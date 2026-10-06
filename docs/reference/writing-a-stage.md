# Writing a stage

This guide takes you from an empty file to a registered, tested stage: a small worked example, its entry-point registration, a unit test, a checklist, and the rules for packaging a stage as a third-party plugin. The contracts behind it are in the [pipeline reference](pipeline.md).

Every `python test` block on this page is executed by `tests/docs/test_pipeline_docs.py`. The same module copies the worked example into a fake distribution, lets the registry discover it, checks it with `describe_stage` and runs it inside `run_scan`, so the example is known to work and cannot rot.

## What a stage is

A stage reads some artefact keys, writes others, and is wired into a scan only by those declarations. It does not call other stages, and it does not know what ran before it. The orchestrator orders stages, runs the independent ones side by side, caches the cacheable ones, applies the failure policy and publishes events; the stage does its own work and declares truthfully what it needs and produces.

## A worked example: `analyse-todo`

`analyse-todo` is an `analyse` stage. It reads the files listed in the `files` artefact and reports every `# TODO` comment as a candidate. Candidates are a Pydantic model, because a consumer reads the parts of `candidates.raw` back as models.

```python test
# file: ck_todo.py
"""A stage that reports TODO comments as candidates."""

import re

from pydantic import BaseModel

from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.stage import StageCategory

TODO = re.compile(r"#\s*TODO\b")


class TodoCandidate(BaseModel):
    """One TODO comment; the path is relative to the project root."""

    path: str
    line: int
    kind: str = "todo"


class AnalyseTodo:
    """Reads the files listed in ``files`` and reports every ``# TODO`` line."""

    name = "analyse-todo"
    requires = frozenset({"files"})
    provides = frozenset({"candidates.raw"})
    category = StageCategory.ANALYSE
    version = "1"

    def run(self, ctx: RunContext) -> None:
        listing = ctx.artefacts.get_json("files")
        entries = listing if isinstance(listing, list) else []
        paths = sorted(str(entry["path"]) for entry in entries if isinstance(entry, dict))
        found: list[TodoCandidate] = []
        for index, relative in enumerate(paths, start=1):
            ctx.check_cancelled()
            ctx.emit_progress(index, len(paths), "files")
            try:
                text = (ctx.project_root / relative).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                ctx.warn("file_unreadable")  # a machine code: no path, no message
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if TODO.search(line):
                    found.append(TodoCandidate(path=relative, line=number))
        ctx.artefacts.put_part("candidates.raw", self.name, found)
```

What each part does:

- **Declarations.** `requires = {"files"}` and `provides = {"candidates.raw"}` are all the orchestrator knows. `candidates.raw` is a multi-provider key: several `analyse-*` stages each write a part under their own name, and `aggregate` reads them together in part-name order.
- **Category.** `StageCategory.ANALYSE` gives the stage the defaults of its category: the `degrade` failure policy (a failure here does not stop the scan), cacheable, not salt dependent. Without a category the stage would be fail-closed, not cacheable and blocked after an egress lockout.
- **Version.** The stage cache key contains `version`. Bump it whenever the output can change, for example when the pattern changes.
- **Cancellation.** `ctx.check_cancelled()` once per file lets the scan stop between files; it raises `ScanCancelledError` when the scan is cancelled or its time is used up.
- **Progress and warnings.** `ctx.emit_progress(current, total, unit)` publishes `StageProgress`; `ctx.warn(code)` publishes a warning that is a machine code. Neither takes a path, an identifier from client code or a message.
- **Determinism.** The paths are sorted and the candidates are stored in file and line order, so the same repository gives the same artefact, byte for byte.
- **Output.** `put_part` writes the stage's part. A stage that returns without writing every key it provides fails with `missing_provides`.

## Register it

A stage is found through the `codekavach.stages` entry-point group. In the `pyproject.toml` of the package that contains it:

```toml
[project.entry-points."codekavach.stages"]
analyse-todo = "ck_todo:AnalyseTodo"
```

The name before the equals sign must equal the stage's `name`; the target names a callable that returns the stage, here the class. The registry reads the distribution metadata first and imports the module only when the stage is used, and an operator's `[plugins]` settings are applied before the import (see [Third-party plugin packages](#third-party-plugin-packages)).

## Test it

Test the stage on its own with the shared kit of this repository, `tests.support.pipeline`: `make_run_context` builds a `RunContext` with an in-memory store, and `FakeStage` stands in for the stages around yours. The test below runs `analyse-todo` between a fake `ingest` and a fake `aggregate` and reads the part back.

```python test
import tempfile
from pathlib import Path

from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.stage import StageCategory
from tests.support.pipeline import FakeStage, make_run_context


def test_analyse_todo_reports_the_todo_lines() -> None:
    root = Path(tempfile.mkdtemp())
    (root / "a.py").write_text("x = 1\n# TODO: handle errors\ny = 2\n", encoding="utf-8")
    (root / "b.py").write_text("print('clean')\n", encoding="utf-8")
    ingest = FakeStage(
        "ingest",
        requires={"scan.target"},
        provides={"files"},
        category=StageCategory.INGEST,
        writes={"files": [{"path": "b.py"}, {"path": "a.py"}]},
    )
    aggregate = FakeStage(
        "aggregate",
        requires={"candidates.raw"},
        provides={"candidates"},
        category=StageCategory.AGGREGATE,
        writes={"candidates": []},
    )
    ctx = make_run_context(project_root=root)
    ctx.artefacts.put("scan.target", {"target": str(root)})

    result = Orchestrator().run(plan_from_stages([ingest, AnalyseTodo(), aggregate]), ctx)

    run = result.run_of("analyse-todo")
    assert run is not None and run.outcome is StageOutcome.SUCCEEDED
    parts = ctx.artefacts.get_parts("candidates.raw", TodoCandidate)
    assert parts == {"analyse-todo": [TodoCandidate(path="a.py", line=2)]}
    assert aggregate.seen["candidates.raw"] == ["analyse-todo"]  # the neighbour saw the part


def test_a_missing_file_is_a_warning_not_a_failure() -> None:
    root = Path(tempfile.mkdtemp())
    (root / "a.py").write_text("# TODO\n", encoding="utf-8")
    ingest = FakeStage(
        "ingest",
        requires={"scan.target"},
        provides={"files"},
        category=StageCategory.INGEST,
        writes={"files": [{"path": "a.py"}, {"path": "gone.py"}]},
    )
    ctx = make_run_context(project_root=root)
    ctx.artefacts.put("scan.target", {"target": str(root)})
    result = Orchestrator().run(plan_from_stages([ingest, AnalyseTodo()]), ctx)
    run = result.run_of("analyse-todo")
    assert run is not None and run.outcome is StageOutcome.SUCCEEDED
    assert ctx.artefacts.get_parts("candidates.raw", TodoCandidate)["analyse-todo"][0].line == 1
```

A test that runs the whole pipeline of a scan uses `run_scan` with a registry that contains your stage; `tests/integration/core/test_run_scan.py` shows how a fake distribution is built.

## Checklist

1. Declare `name`, `requires` and `provides` truthfully; the scoped store refuses undeclared access.
2. Set `category`. Without it the stage is fail-closed, not cacheable and blocked after an egress lockout.
3. Bump `version` whenever the output can change, and include every influence on the output in memo keys.
4. Call `ctx.check_cancelled()` once per unit of work and pass `ctx.remaining_seconds()` to subprocess and network timeouts.
5. Report per-item problems with `ctx.fail_item()` or `guard_item`; raise only when the whole stage cannot work.
6. Keep paths, identifiers, code and exception messages out of events, item failures and log messages at INFO and above; log exception classes and keep tracebacks at DEBUG.
7. Store only Pydantic models, lists of one model class or JSON values; declare transient objects in `transient_provides`.
8. Be deterministic: sort collections before storing, use no wall-clock time or randomness in results, and read no environment variable.
9. Open no network connection. LLM access goes through the egress transport only (I1); an LLM-category stage reads sanitised payloads only (I2).
10. Leave the vault and the salt alone unless you are a privacy or restore stage, and do not log or store either (I3).

Why the sixth item matters: events, item failures and the manifest are designed to travel, so their fields are restricted to tokens and numbers, which keeps paths and messages out. The check cannot recognise an identifier taken from client code, so the rule is yours to keep.

## Third-party plugin packages

A stage, language, engine, detector, provider or renderer can ship in its own package. The entry-point groups are `codekavach.stages`, `codekavach.languages`, `codekavach.engines`, `codekavach.detectors`, `codekavach.providers` and `codekavach.renderers`.

- **Naming.** Name the distribution after its owner and purpose, for example `acme-codekavach-rules`, and the stage with a prefix of your own so that it cannot collide with another plugin, for example `acme-analyse-todo`. A name is lower-case letters, digits and hyphens, at most 48 characters.
- **Name collisions.** Two plugins with the same group and name resolve deterministically: the `codekavach` distribution wins, otherwise the alphabetically first distribution name; the others are listed as `shadowed`.
- **Plugin API.** A stage may declare `plugin_api = 1`, the version this release supports. A stage that declares another value is refused with `StageDeclarationError`, and the registry reports it as a failed plugin by exception class, without a message.
- **Allow-list.** An operator can restrict which distributions may contribute code with `plugins.allow_distributions` and switch single plugins off with `plugins.disable` (for example `stage:acme-analyse-todo`). Distribution names are compared after PEP 503 normalisation, so `Acme_CodeKavach.Rules` and `acme-codekavach-rules` are the same distribution, and `codekavach` itself is always allowed. The policy is applied before anything is imported: a plugin that is not allowed is listed as `disabled` and its module is not loaded (`tests/integration/core/test_plugin_policy.py` imports a fake distribution to prove it). Both keys are restricted settings, so a scanned repository cannot change them through its own `codekavach.toml`.
- **Failures.** A plugin that fails to import, to construct or to validate is left out and recorded by exception class name only; the scan goes on. `codekavach doctor` reports it.
- **Versions.** The registry records `<distribution>==<version>` as the stage's `origin`, which is part of the cache key, so a stage cache entry from an older release of your package is not reused after an upgrade.

## Known limits

- Plugin code is trusted code and is not sandboxed. The allow-list narrows which installed code runs; it does not constrain what an allowed plugin does with the rights of the process.
- The scoped store is a guard against mistakes, not a security boundary.
- A resumed scan may send identical payloads again until the LLM response cache exists.
- Pruning deletes with `unlink`; pruned client data may remain recoverable from the disk until its blocks are reused.
- The integrity checks of the cache detect corruption and casual tampering, not a determined local attacker.
