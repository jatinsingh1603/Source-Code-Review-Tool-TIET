"""Golden path slices over ``tests/fixtures/slicing/paths`` (E11-03).

Each folder holds ``src/`` (the repository) and ``case.json``: the sink, the optional source and
steps of a taint path, the budget, the files never sent, the callee depth and which strategies to
run. One golden per strategy records the status, the strategy, the recall record, the fallback
reason and the assembled text. Rewrite goldens with ``CODEKAVACH_UPDATE_GOLDEN=1`` and read the
diff.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models import CodeSlice, SliceStrategy
from codekavach.parsing import parse
from codekavach.privacy.slicing.assemble import assemble, file_text, numbered_labels
from codekavach.privacy.slicing.base import SliceRefusal, SlicingError, outcome_for
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import never_send_matcher
from codekavach.privacy.slicing.select import StrategySelector
from codekavach.privacy.slicing.strategies.backward import BackwardSliceStrategy
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.slicing.strategies.forward import ForwardSliceStrategy
from codekavach.privacy.slicing.strategies.hotspot import HotspotStrategy
from codekavach.privacy.slicing.strategies.taintpath import TaintPathStrategy
from codekavach.privacy.slicing.strategies.window import SinkWindowStrategy
from tests.support.golden import assert_matches_golden
from tests.support.slicing import candidate_at, language_of, make_index, taint_candidate

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "slicing" / "paths"
CASES = sorted(path for path in FIXTURES.iterdir() if (path / "case.json").is_file())
PAIRS = [
    (folder, name)
    for folder in CASES
    for name in json.loads((folder / "case.json").read_text(encoding="utf-8"))["strategies"]
]


def load(folder: Path) -> tuple[dict[str, Any], dict[str, str]]:
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    sources = {
        path.relative_to(folder / "src").as_posix(): path.read_text(encoding="utf-8")
        for path in sorted((folder / "src").rglob("*"))
        if path.is_file()
    }
    return meta, sources


def strategy_for(name: str, depth: int) -> Any:
    return {
        "taint_path": TaintPathStrategy(callee_depth=depth),
        "backward_slice": BackwardSliceStrategy(),
        "forward_slice": ForwardSliceStrategy(),
        "sink_window": SinkWindowStrategy(),
        "enclosing_function": EnclosingFunctionStrategy(),
        "hotspot": HotspotStrategy(),
    }[name]


def run(folder: Path, name: str) -> tuple[CodeSlice | SliceRefusal, dict[str, str]]:
    meta, sources = load(folder)
    patterns = meta["never_send"]
    never = never_send_matcher(Settings.model_validate({"privacy": {"never_send": patterns}}))
    index = make_index(sources, never_send=never if patterns else None)
    sink = tuple(meta["sink"])
    if meta["source"] is not None:
        candidate = taint_candidate(
            tuple(meta["source"]), sink, *[tuple(step) for step in meta["between"]]
        )
    else:
        candidate = candidate_at(*sink)
    outcome = outcome_for(
        strategy_for(name, meta["callee_depth"]),
        candidate,
        index,
        budget=SliceBudget(meta["budget"]),
    )
    return outcome, sources


def render(outcome: CodeSlice | SliceRefusal) -> str:
    if isinstance(outcome, SliceRefusal):
        return f"refused: {outcome.reason}\n"
    labels = numbered_labels(outcome.files)
    lines = [
        "status: slice",
        f"strategy: {outcome.strategy.value}",
        f"purpose: {outcome.purpose.value}",
        f"fallback: {outcome.fallback_reason}",
        f"recall: {outcome.recall}",
        f"truncated: {outcome.truncated}",
        f"tokens: {outcome.token_estimate}",
        "---",
        assemble(outcome.segments, outcome.stubs, language=outcome.language, labels=labels),
    ]
    return "\n".join(lines) + "\n"


def test_there_are_at_least_twenty_cases_in_three_languages() -> None:
    assert len(CASES) >= 20
    languages = {language_of(next(iter(load(folder)[1]))).value for folder in CASES}
    assert {"python", "javascript", "typescript"} <= languages


@pytest.mark.parametrize(
    ("folder", "name"), PAIRS, ids=lambda v: v.name if isinstance(v, Path) else v
)
def test_the_slice_matches_its_golden(folder: Path, name: str) -> None:
    outcome, _ = run(folder, name)
    assert_matches_golden(render(outcome), folder / f"golden_{name}.txt")


@pytest.mark.parametrize(
    ("folder", "name"), PAIRS, ids=lambda v: v.name if isinstance(v, Path) else v
)
def test_every_slice_parses_in_its_language(folder: Path, name: str) -> None:
    outcome, _ = run(folder, name)
    if isinstance(outcome, SliceRefusal):
        pytest.skip("refused")
    for path in outcome.files:
        text = file_text([s for s in outcome.segments if s.path == path], outcome.language)
        assert parse(path, language_of(path), text).error_count == 0, path


@pytest.mark.parametrize(
    ("folder", "name"), PAIRS, ids=lambda v: v.name if isinstance(v, Path) else v
)
def test_the_slice_is_byte_identical_on_a_second_run(folder: Path, name: str) -> None:
    first, _ = run(folder, name)
    second, _ = run(folder, name)
    assert render(first) == render(second)
    if isinstance(first, CodeSlice) and isinstance(second, CodeSlice):
        assert first.model_dump_json() == second.model_dump_json()


@pytest.mark.parametrize("folder", CASES, ids=lambda folder: folder.name)
def test_the_selector_picks_the_richest_strategy_and_records_why(folder: Path) -> None:
    meta, sources = load(folder)
    patterns = meta["never_send"]
    never = never_send_matcher(Settings.model_validate({"privacy": {"never_send": patterns}}))
    index = make_index(sources, never_send=never if patterns else None)
    candidate = candidate_at(*tuple(meta["sink"]))
    if meta["source"] is not None:
        candidate = taint_candidate(
            tuple(meta["source"]), tuple(meta["sink"]), *[tuple(s) for s in meta["between"]]
        )
    try:
        built = StrategySelector(callee_depth=meta["callee_depth"]).build(
            candidate, index, budget=SliceBudget(meta["budget"])
        )
    except SlicingError:
        return
    if meta["source"] is not None and built.strategy is not SliceStrategy.TAINT_PATH:
        assert built.fallback_reason is not None
