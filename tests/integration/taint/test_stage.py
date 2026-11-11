"""``AnalyseTaintStage`` through the pipeline context (E17-02)."""

import hashlib
import json
from pathlib import Path

import pytest

from codekavach.analysis.rules.loader import load_pack
from codekavach.analysis.taint import propagate
from codekavach.analysis.taint import stage as taint_stage
from codekavach.analysis.taint.stage import TAINT_ENGINE, AnalyseTaintStage
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.memo import DiskItemMemo
from codekavach.core.store.layout import StateLayout
from codekavach.ingest.models import SourceFile
from codekavach.parsing.symbols import SymbolsArtefact
from tests.support.pipeline import make_run_context

ROOT = Path(__file__).resolve().parents[3]
PACK = load_pack(ROOT / "rules" / "mit" / "packs" / "default")
CODE = (
    "import os\nfrom flask import request\n\n"
    "def vulnerable():\n    name = request.args.get('name')\n    os.system('ls ' + name)\n\n"
    "def safe():\n    os.system('ls')\n"
)
STAGE = "analyse-taint"


def context(tmp_path: Path, settings: Settings | None = None, code: str = CODE) -> RunContext:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "app.py").write_text(code, encoding="utf-8")
    memo = DiskItemMemo(StateLayout(tmp_path / "state"))
    base = make_run_context(settings=settings or Settings(), project_root=project)
    ctx = base.for_stage(STAGE, memo=memo)
    file = SourceFile(
        path="app.py",
        sha256=hashlib.sha256(code.encode()).hexdigest(),
        size_bytes=len(code),
        language=Language.PYTHON,
        line_count=code.count("\n"),
        encoding="utf-8",
    )
    ctx.artefacts.put(keys.FILES, [file])
    ctx.artefacts.put(keys.SYMBOLS, SymbolsArtefact(tables={}))
    return ctx


def run(ctx: RunContext) -> list[Candidate]:
    AnalyseTaintStage(packs=[PACK]).run(ctx)
    return ctx.artefacts.get_parts(keys.CANDIDATES_RAW, Candidate).get(STAGE, [])


def test_the_stage_contract() -> None:
    assert AnalyseTaintStage.name == "analyse-taint"
    assert AnalyseTaintStage.requires == frozenset({keys.FILES, keys.SYMBOLS})
    assert AnalyseTaintStage.provides == frozenset({keys.CANDIDATES_RAW})
    assert AnalyseTaintStage.optional_requires == frozenset({keys.AST, keys.CALL_GRAPH})


def test_the_stage_emits_one_candidate_with_a_valid_path(tmp_path: Path) -> None:
    (candidate,) = run(context(tmp_path))
    assert candidate.engine == TAINT_ENGINE
    assert candidate.rule_id == "taint.http_param.shell"
    assert candidate.cwe == (78,)
    assert candidate.taint_path is not None and len(candidate.taint_path) == 2
    assert candidate.primary_location.symbol == "vulnerable"
    assert candidate.message and "ls" not in candidate.message


def test_native_taint_off_publishes_an_empty_part(tmp_path: Path) -> None:
    settings = Settings.model_validate({"engines": {"native": {"taint": False}}})
    ctx = context(tmp_path, settings)
    assert run(ctx) == []
    assert ctx.artefacts.has(keys.CANDIDATES_RAW)


def test_a_second_scan_reuses_the_memoised_lowering(tmp_path: Path) -> None:
    first = context(tmp_path)
    run(first)
    assert (first.memo.stats().hits, first.memo.stats().misses) == (0, 1)
    second = context(tmp_path)
    again = run(second)
    assert (second.memo.stats().hits, second.memo.stats().misses) == (1, 0)
    assert len(again) == 1


def test_a_function_that_raises_is_an_item_failure_and_the_others_still_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = propagate.propagate_bound

    def flaky(function, *args, **kwargs):  # type: ignore[no-untyped-def]
        if function.name == "safe":
            raise RuntimeError("boom")
        return real(function, *args, **kwargs)

    monkeypatch.setattr(taint_stage, "propagate_bound", flaky)
    ctx = context(tmp_path)
    assert len(run(ctx)) == 1
    failures = ctx.item_failures.snapshot()
    assert [f.error_code for f in failures] == ["taint_error"]
    assert "boom" not in failures[0].item_id


def test_a_function_over_its_time_budget_is_a_timeout_item_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def slow(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise propagate.BudgetExceededError

    monkeypatch.setattr(taint_stage, "propagate_bound", slow)
    ctx = context(tmp_path)
    assert run(ctx) == []
    assert {f.error_code for f in ctx.item_failures.snapshot()} == {"taint_timeout"}


def test_explain_writes_only_under_the_state_directory(tmp_path: Path) -> None:
    settings = Settings.model_validate({"taint": {"explain": True}})
    ctx = context(tmp_path, settings)
    state = tmp_path / "scan-state"
    object.__setattr__(ctx, "state_dir", state)
    candidates = run(ctx)
    dumps = sorted((state / "taint").glob("*.json"))
    assert dumps and sorted((state / "taint").glob("*.dot"))
    text = "".join(path.read_text(encoding="utf-8") for path in dumps)
    assert "vulnerable" in text and json.loads(dumps[0].read_text(encoding="utf-8"))
    everywhere = [p for p in tmp_path.rglob("*") if p.is_file()]
    elsewhere = [p for p in everywhere if state not in p.parents and p.suffix in {".dot"}]
    assert elsewhere == []
    for candidate in candidates:
        blob = candidate.model_dump_json()
        assert "digraph" not in blob and "statements" not in blob


def test_explain_off_writes_nothing(tmp_path: Path) -> None:
    ctx = context(tmp_path)
    state = tmp_path / "scan-state"
    object.__setattr__(ctx, "state_dir", state)
    run(ctx)
    assert not (state / "taint").exists()
