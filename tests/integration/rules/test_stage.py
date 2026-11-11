"""``AnalyseRulesStage`` driving the DSL packs through the pipeline context (E16-02)."""

import hashlib
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from codekavach.analysis.rules.base import GeneratorRegistry
from codekavach.analysis.rules.loader import load_pack
from codekavach.analysis.rules.pack import RulePack
from codekavach.analysis.rules.stage import RULES_ENGINE, AnalyseRulesStage
from codekavach.config import Settings
from codekavach.core.models import Candidate, Language, Severity
from codekavach.core.models.fingerprint import FINGERPRINT_PATTERN
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.memo import DiskItemMemo
from codekavach.core.store.layout import StateLayout
from codekavach.ingest.models import SourceFile
from codekavach.parsing.symbols import SymbolsArtefact
from tests.support.pipeline import make_run_context
from tests.support.rule_files import rule_data, write_pack

CODE = (
    "def find(owner, cur):\n"
    '    cur.execute("SELECT * FROM accounts WHERE owner = \'" + owner + "\'")\n'
    '    cur.execute("SELECT * FROM accounts WHERE owner = ?", (owner,))\n'
)
STAGE = "analyse-rules"


def stage_context(
    tmp_path: Path, *, settings: Settings | None = None, memo: DiskItemMemo | None = None
) -> RunContext:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "app.py").write_text(CODE, encoding="utf-8")
    base = make_run_context(settings=settings or Settings(), project_root=project)
    ctx = base.for_stage(STAGE, memo=memo)
    file = SourceFile(
        path="app.py",
        sha256=hashlib.sha256(CODE.encode()).hexdigest(),
        size_bytes=len(CODE),
        language=Language.PYTHON,
        line_count=CODE.count(chr(10)),
        encoding="utf-8",
    )
    ctx.artefacts.put(keys.FILES, [file])
    ctx.artefacts.put(keys.SYMBOLS, SymbolsArtefact(tables={}))
    return ctx


def pack_with(base: Path, *rules: dict[str, Any]) -> RulePack:
    texts = {f"r{n}.yaml": yaml.safe_dump(item, sort_keys=False) for n, item in enumerate(rules)}
    return load_pack(write_pack(base / "rules", rules=texts))


def run(ctx: RunContext, packs: Sequence[RulePack]) -> list[Candidate]:
    AnalyseRulesStage(registry=GeneratorRegistry(), packs=packs).run(ctx)
    return ctx.artefacts.get_parts(keys.CANDIDATES_RAW, Candidate).get(STAGE, [])


def disk_memo(tmp_path: Path) -> DiskItemMemo:
    return DiskItemMemo(StateLayout(tmp_path / "state"))


def test_the_worked_example_yields_one_valid_candidate(tmp_path: Path) -> None:
    pack = pack_with(tmp_path, rule_data())
    (candidate,) = run(stage_context(tmp_path), [pack])
    assert candidate.engine == RULES_ENGINE == "codekavach-rules"
    assert candidate.rule_id == "python.sqli.cursor-execute-concat"
    assert candidate.cwe == (89,)
    assert candidate.engine_severity is Severity.HIGH
    assert candidate.engine_version == "default@1.0.0"
    assert candidate.primary_location.start_line == 2
    assert candidate.primary_location.symbol == "find"
    assert re.fullmatch(FINGERPRINT_PATTERN, candidate.fingerprint)
    assert candidate.message == "SQL query built by string concatenation"


def test_a_rule_that_raises_is_reported_and_the_others_still_produce(tmp_path: Path) -> None:
    bad = rule_data(id="python.misc.bad", match={"any": [{"pattern": "def ("}]})
    pack = pack_with(tmp_path, bad, rule_data())
    ctx = stage_context(tmp_path)
    candidates = run(ctx, [pack])
    assert [c.rule_id for c in candidates] == ["python.sqli.cursor-execute-concat"]
    failures = ctx.item_failures.snapshot()
    assert [(f.item_id, f.error_code) for f in failures] == [("python.misc.bad", "rule_error")]


def test_native_rules_off_runs_the_stage_and_provides_an_empty_part(tmp_path: Path) -> None:
    pack = pack_with(tmp_path, rule_data())
    settings = Settings.model_validate({"engines": {"native": {"rules": False}}})
    ctx = stage_context(tmp_path, settings=settings)
    assert run(ctx, [pack]) == []
    assert ctx.artefacts.has(keys.CANDIDATES_RAW)


def test_a_second_scan_is_served_from_the_match_cache(tmp_path: Path) -> None:
    pack = pack_with(tmp_path, rule_data())
    first = disk_memo(tmp_path)
    run(stage_context(tmp_path, memo=first), [pack])
    assert (first.stats().hits, first.stats().misses) == (0, 1)
    second = disk_memo(tmp_path)
    again = run(stage_context(tmp_path, memo=second), [pack])
    assert (second.stats().hits, second.stats().misses) == (1, 0)
    assert [c.rule_id for c in again] == ["python.sqli.cursor-execute-concat"]


def test_a_changed_pack_misses_the_cache(tmp_path: Path) -> None:
    run(stage_context(tmp_path, memo=disk_memo(tmp_path)), [pack_with(tmp_path, rule_data())])
    changed = pack_with(tmp_path / "other", rule_data(message="Another message"))
    memo = disk_memo(tmp_path)
    run(stage_context(tmp_path, memo=memo), [changed])
    assert (memo.stats().hits, memo.stats().misses) == (0, 1)


def test_a_failing_rule_is_not_cached(tmp_path: Path) -> None:
    bad = rule_data(id="python.misc.bad", match={"any": [{"pattern": "def ("}]})
    pack = pack_with(tmp_path, bad, rule_data())
    for _ in range(2):
        memo = disk_memo(tmp_path)
        ctx = stage_context(tmp_path, memo=memo)
        run(ctx, [pack])
        assert memo.stats().hits == 0
        assert len(ctx.item_failures.snapshot()) == 1
