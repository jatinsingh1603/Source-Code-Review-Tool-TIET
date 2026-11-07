"""The KavachBank fixture through ``run_scan`` with the real stages (E13-01).

ingest, parse, analyse-rules and aggregate run on a copy of ``fixtures/kavachbank``; the candidates
are compared with the ground-truth manifest: every ``demo_1`` entry is found at the right file and
within a small line tolerance, no negative control produces a candidate, and nothing else does.
"""

import shutil
from pathlib import Path

import pytest

from codekavach.analysis.aggregate.stage import AggregateStage
from codekavach.analysis.rules.stage import AnalyseRulesStage
from codekavach.config import load_settings
from codekavach.core.models import Candidate, CandidateKind, ScanStatus
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.support.ingest import SALT_HEX, stages_registry
from tests.support.kavachbank import (
    FIXTURE_ROOT,
    load_manifest,
    load_negative_controls,
)

LINE_TOLERANCE = 2
STAGES = ("ingest", "parse", "analyse-rules", "aggregate")


def copy_fixture(into: Path) -> Path:
    root = into / "kavachbank"
    shutil.copytree(FIXTURE_ROOT, root)
    (root / ".git").mkdir()
    return root


def scan(root: Path) -> ScanOutcome:
    loaded = load_settings(target=root, env={"CODEKAVACH_HOME": str(root.parent / "home")})
    return run_scan(
        loaded,
        str(root),
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=stages_registry(*STAGES),
        persist=False,
    )


def store_of(outcome: ScanOutcome) -> OnDiskArtefactStore:
    return OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)


@pytest.fixture(scope="module")
def root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return copy_fixture(tmp_path_factory.mktemp("kavachbank"))


@pytest.fixture(scope="module")
def outcome(root: Path) -> ScanOutcome:
    return scan(root)


@pytest.fixture(scope="module")
def candidates(outcome: ScanOutcome) -> list[Candidate]:
    return store_of(outcome).get_list(keys.CANDIDATES, Candidate)


def near(candidate: Candidate, file: str, line: int) -> bool:
    location = candidate.primary_location
    return location.path == file and abs(location.start_line - line) <= LINE_TOLERANCE


def test_the_four_stages_run_in_the_default_order_without_manual_ordering(
    outcome: ScanOutcome,
) -> None:
    assert outcome.scan.status is ScanStatus.COMPLETED
    runs = outcome.result.stage_runs
    assert [run.stage for run in runs] == list(STAGES)
    assert all(run.outcome is StageOutcome.SUCCEEDED for run in runs)


def test_the_stage_metadata_matches_the_pipeline_table() -> None:
    infos = stages_registry(*STAGES).stage_infos()
    rules, aggregate = infos["analyse-rules"], infos["aggregate"]
    assert rules.requires == {keys.FILES, keys.SYMBOLS}
    assert rules.optional_requires == {keys.AST, keys.CALL_GRAPH}
    assert rules.provides == {keys.CANDIDATES_RAW}
    assert rules.category is StageCategory.ANALYSE
    assert rules.failure_policy is FailurePolicy.DEGRADE
    assert aggregate.requires == {keys.CANDIDATES_RAW}
    assert aggregate.provides == {keys.CANDIDATES}
    assert aggregate.category is StageCategory.AGGREGATE
    assert aggregate.failure_policy is FailurePolicy.ABORT_SCAN
    assert AnalyseRulesStage.name == "analyse-rules" and AggregateStage.name == "aggregate"


def test_the_artefacts_have_the_documented_shapes(
    outcome: ScanOutcome, candidates: list[Candidate]
) -> None:
    parts = store_of(outcome).get_parts(keys.CANDIDATES_RAW, Candidate)
    assert list(parts) == ["analyse-rules"]
    assert sorted(c.fingerprint for c in parts["analyse-rules"]) == sorted(
        c.fingerprint for c in candidates
    )
    assert candidates
    for candidate in candidates:
        assert candidate.engine == "codekavach.rules"
        assert candidate.kind is CandidateKind.VULNERABILITY
        assert candidate.cwe and candidate.engine_severity is not None
        assert len(candidate.locations) == 1 and candidate.taint_path is None


def test_the_candidates_are_ordered_and_unique(candidates: list[Candidate]) -> None:
    order = [
        (c.primary_location.path, c.primary_location.start_line, c.rule_id) for c in candidates
    ]
    assert order == sorted(order)
    assert len({c.fingerprint for c in candidates}) == len(candidates)


def test_every_demo_1_entry_is_found_at_the_right_place(candidates: list[Candidate]) -> None:
    missed = [
        entry.id
        for entry in load_manifest().demo_1_vulnerabilities()
        if not any(near(c, entry.file, entry.line) and entry.cwe in c.cwe for c in candidates)
    ]
    assert missed == []


def test_no_negative_control_produces_a_candidate(candidates: list[Candidate]) -> None:
    flagged = [
        control.id
        for control in load_negative_controls()
        for c in candidates
        if c.primary_location.path == control.file
        and c.primary_location.start_line <= control.line <= c.primary_location.end_line
    ]
    assert flagged == []


def test_nothing_else_is_reported(candidates: list[Candidate]) -> None:
    planted = load_manifest().planted_vulnerabilities
    strays = [
        (c.primary_location.path, c.primary_location.start_line, c.rule_id)
        for c in candidates
        if not any(near(c, entry.file, entry.line) for entry in planted)
    ]
    assert strays == []
    assert len(candidates) == len(planted)


def test_a_second_scan_gives_the_same_fingerprints_in_the_same_order(
    tmp_path: Path, candidates: list[Candidate]
) -> None:
    again = store_of(scan(copy_fixture(tmp_path))).get_list(keys.CANDIDATES, Candidate)
    assert [c.fingerprint for c in again] == [c.fingerprint for c in candidates]


def test_a_whitespace_edit_of_an_unrelated_line_keeps_the_fingerprints(
    tmp_path: Path, candidates: list[Candidate]
) -> None:
    edited_root = copy_fixture(tmp_path)
    target = edited_root / "services" / "api" / "fee_schedule.py"
    target.write_text(
        target.read_text(encoding="utf-8").replace("GST_RATE = Decimal", "GST_RATE  =  Decimal  "),
        encoding="utf-8",
    )
    again = store_of(scan(edited_root)).get_list(keys.CANDIDATES, Candidate)
    assert [c.fingerprint for c in again] == [c.fingerprint for c in candidates]


def test_a_line_added_above_a_weakness_moves_it_but_keeps_its_fingerprint(
    tmp_path: Path, candidates: list[Candidate]
) -> None:
    shifted_root = copy_fixture(tmp_path)
    target = shifted_root / "services" / "api" / "accounts.py"
    target.write_text("# reviewed\n" + target.read_text(encoding="utf-8"), encoding="utf-8")
    again = store_of(scan(shifted_root)).get_list(keys.CANDIDATES, Candidate)
    assert {c.fingerprint for c in again} == {c.fingerprint for c in candidates}
    moved = next(c for c in again if c.rule_id == "py.sql-injection")
    assert moved.primary_location.start_line == 12


def test_the_scan_without_the_parse_stage_artefact_still_finds_everything(
    tmp_path: Path, candidates: list[Candidate], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The `ast` artefact is optional: the stage parses a file itself when the mapping lacks it.
    monkeypatch.setattr(AnalyseRulesStage, "_ast", staticmethod(lambda ctx: None))
    again = store_of(scan(copy_fixture(tmp_path))).get_list(keys.CANDIDATES, Candidate)
    assert [c.fingerprint for c in again] == [c.fingerprint for c in candidates]
