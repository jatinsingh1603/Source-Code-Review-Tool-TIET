"""Code flows to taint paths (E14-02)."""

from pathlib import Path
from typing import Any

import pytest

from codekavach.analysis.engines.sarif.codeflows import MAX_CODE_FLOW_STEPS, code_flow_to_taint_path
from codekavach.analysis.engines.sarif.locations import SourceCache
from codekavach.analysis.engines.sarif.model import CodeFlow, Run
from codekavach.core.models.enums import TaintRole
from codekavach.core.models.taint import MAX_NOTE_LENGTH
from tests.support.sarif import code_flow, numbered_source, step, write_tree


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return write_tree(
        tmp_path / "view", {"a.py": numbered_source(200), "b.py": numbered_source(20)}
    )


def convert(
    root: Path, *steps: dict[str, Any], order: Any = "source_first", run: Run | None = None
) -> Any:
    flow = CodeFlow.model_validate(code_flow(*steps))
    return code_flow_to_taint_path(flow, run or Run(), root, SourceCache(root), order=order)


def test_source_first_flow_gets_the_three_roles(root: Path) -> None:
    path = convert(root, step("a.py", 3, "taint enters"), step("a.py", 5), step("b.py", 7, "query"))
    assert path is not None
    assert [s.role for s in path.steps] == [TaintRole.SOURCE, TaintRole.PROPAGATOR, TaintRole.SINK]
    assert [(s.location.path, s.location.start_line) for s in path.steps] == [
        ("a.py", 3),
        ("a.py", 5),
        ("b.py", 7),
    ]
    assert path.steps[0].note == "taint enters"
    assert path.steps[1].note is None


def test_a_sink_first_flow_is_reversed(root: Path) -> None:
    path = convert(
        root, step("b.py", 7, "query"), step("a.py", 5), step("a.py", 3), order="sink_first"
    )
    assert path is not None
    assert path.source.location.start_line == 3
    assert path.sink.location.path == "b.py"
    assert path.source.role is TaintRole.SOURCE


def test_a_single_location_is_rejected(root: Path) -> None:
    assert convert(root, step("a.py", 3)) is None


def test_steps_that_cannot_be_located_are_dropped(root: Path) -> None:
    path = convert(
        root, step("a.py", 3), step("../../etc/passwd", 1), step("missing.py", 1), step("a.py", 9)
    )
    assert path is not None
    assert [s.location.start_line for s in path.steps] == [3, 9]
    assert convert(root, step("a.py", 3), step("../x.py", 1)) is None


def test_a_sanitiser_step_keeps_its_role_in_the_middle(root: Path) -> None:
    kinded = step("a.py", 4, kinds=["sanitizer"])
    flagged = step("a.py", 5, properties={"sanitiser": True})
    path = convert(root, step("a.py", 3), kinded, flagged, step("a.py", 6), step("a.py", 9))
    assert path is not None
    assert [s.role for s in path.steps] == [
        TaintRole.SOURCE,
        TaintRole.SANITISER,
        TaintRole.SANITISER,
        TaintRole.PROPAGATOR,
        TaintRole.SINK,
    ]
    assert path.is_sanitised


def test_a_sanitiser_at_an_end_cannot_replace_source_or_sink(root: Path) -> None:
    path = convert(root, step("a.py", 3, kinds=["sanitizer"]), step("a.py", 9, kinds=["sanitizer"]))
    assert path is not None
    assert [s.role for s in path.steps] == [TaintRole.SOURCE, TaintRole.SINK]


def test_an_overlong_flow_is_trimmed_by_importance_keeping_both_ends(root: Path) -> None:
    steps = [
        step("a.py", 1 + index % 190, importance="unimportant" if index % 2 else "important")
        for index in range(150)
    ]
    path = convert(root, *steps)
    assert path is not None
    assert len(path.steps) == MAX_CODE_FLOW_STEPS
    assert path.source.location.start_line == 1
    assert path.sink.location.start_line == 1 + 149 % 190
    # 74 middle steps are important (odd lines) and only 62 fit: no unimportant one survives.
    assert all(step.location.start_line % 2 == 1 for step in path.steps[1:-1])


def test_nesting_breaks_ties_when_trimming(root: Path) -> None:
    steps = [step("a.py", 1)]
    steps += [step("a.py", 2 + index, nestingLevel=0 if index < 62 else 5) for index in range(70)]
    steps += [step("a.py", 150)]
    path = convert(root, *steps)
    assert path is not None
    assert len(path.steps) == MAX_CODE_FLOW_STEPS
    assert {s.location.start_line for s in path.steps[1:-1]} >= set(range(2, 20))


def test_a_note_is_truncated_and_never_a_snippet(root: Path) -> None:
    long_text = "word " * 400
    snippet_step = step("a.py", 3, long_text)
    snippet_step["location"]["physicalLocation"]["region"]["snippet"] = {"text": "SNIPPET-MARK"}
    path = convert(root, snippet_step, step("a.py", 4))
    assert path is not None
    note = path.steps[0].note
    assert note is not None
    assert len(note) <= MAX_NOTE_LENGTH
    assert note.endswith("…")
    assert "SNIPPET-MARK" not in path.model_dump_json()


def test_the_function_name_becomes_the_symbol(root: Path) -> None:
    named = step("a.py", 3)
    named["location"]["logicalLocations"] = [{"name": "handler", "kind": "function"}]
    path = convert(root, named, step("a.py", 4))
    assert path is not None
    assert path.steps[0].location.symbol == "handler"


def test_the_first_thread_flow_that_yields_a_path_is_used(root: Path) -> None:
    flow = CodeFlow.model_validate(
        {
            "threadFlows": [
                {"locations": [step("a.py", 3)]},
                {"locations": [step("a.py", 4), step("a.py", 8)]},
            ]
        }
    )
    path = code_flow_to_taint_path(flow, Run(), root, SourceCache(root))
    assert path is not None
    assert path.source.location.start_line == 4
    assert code_flow_to_taint_path(CodeFlow(), Run(), root, SourceCache(root)) is None
