"""Behaviour of the path strategies and the selector (E11-03).

The goldens of ``test_path_fixtures`` pin the text of 27 cases; these tests pin the properties the
issue names: the worked example, control ancestors, the depth cap, termination on a cycle, the
interprocedural cap, the selector's order and its recorded reasons, and the size win over the
enclosing function.
"""

import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.core.models import CandidateKind, SlicePurpose, SliceStrategy
from codekavach.privacy.slicing.base import NotApplicableError, SlicingError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import never_send_matcher
from codekavach.privacy.slicing.select import StrategySelector
from codekavach.privacy.slicing.strategies.backward import BackwardSliceStrategy
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.slicing.strategies.forward import ForwardSliceStrategy
from codekavach.privacy.slicing.strategies.hotspot import (
    HotspotFamily,
    HotspotStrategy,
    SyntacticHotspots,
)
from codekavach.privacy.slicing.strategies.taintpath import TaintPathStrategy
from codekavach.privacy.slicing.strategies.window import SinkWindowStrategy, window_size
from tests.support.slicing import candidate_at, make_index, slice_text, taint_candidate

BUDGET = SliceBudget(2048)
PATHS = Path(__file__).resolve().parents[3] / "fixtures" / "slicing" / "paths"

WORKED = """def transfer(req):
    amount = req.json["amount"]
    note = req.json["note"]
    audit(note)
    if not is_admin(req.user):
        raise Forbidden()
    cur.execute("UPDATE accounts SET bal = bal - " + amount)
    return "ok"
"""


def test_the_worked_example_keeps_source_sink_and_guard_and_nothing_else() -> None:
    index = make_index({"app.py": WORKED})
    candidate = taint_candidate(("app.py", 2), ("app.py", 7))
    text = slice_text(TaintPathStrategy().build(candidate, index, budget=BUDGET))
    assert 'amount = req.json["amount"]' in text
    assert "if not is_admin(req.user):" in text
    assert "raise Forbidden()" in text
    assert "cur.execute(" in text
    assert "audit(note)" not in text
    assert "note" not in text.split("# unresolved")[0]
    assert 'return "ok"' not in text


def test_a_slice_with_a_guard_is_not_an_unconditional_sink() -> None:
    """The guard must reach the model, or it would read the sink as reachable by anyone."""
    index = make_index({"app.py": WORKED})
    candidate = taint_candidate(("app.py", 2), ("app.py", 7))
    for strategy in (TaintPathStrategy(), BackwardSliceStrategy(), ForwardSliceStrategy()):
        assert "is_admin" in slice_text(strategy.build(candidate, index, budget=BUDGET))


def test_every_control_ancestor_of_the_sink_is_kept() -> None:
    source = (PATHS / "p04_nested_guard" / "src" / "app.py").read_text(encoding="utf-8")
    index = make_index({"app.py": source})
    candidate = taint_candidate(("app.py", 2), ("app.py", 5))
    text = slice_text(TaintPathStrategy().build(candidate, index, budget=BUDGET))
    assert "if req.user.is_staff:" in text
    assert "if ident:" in text


def test_the_taint_path_slice_is_smaller_than_the_enclosing_function() -> None:
    smaller = 0
    compared = 0
    for folder in sorted(PATHS.iterdir()):
        meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
        if meta["source"] is None or meta["never_send"] or meta["between"] or meta["budget"] < 1024:
            continue
        sources = {
            p.relative_to(folder / "src").as_posix(): p.read_text(encoding="utf-8")
            for p in (folder / "src").rglob("*")
            if p.is_file()
        }
        index = make_index(sources)
        steps = [tuple(s) for s in meta["between"]]
        candidate = taint_candidate(tuple(meta["source"]), tuple(meta["sink"]), *steps)
        budget = SliceBudget(meta["budget"])
        try:
            path = TaintPathStrategy(callee_depth=meta["callee_depth"]).build(
                candidate, index, budget=budget
            )
            whole = EnclosingFunctionStrategy().build(candidate, index, budget=budget)
        except SlicingError:
            continue
        compared += 1
        assert path.token_estimate <= whole.token_estimate * 1.15, folder.name  # stubs of callees
        smaller += path.token_estimate < whole.token_estimate
    assert compared >= 12
    assert smaller >= compared * 0.5


def test_the_backward_slice_stops_at_the_depth_cap_and_counts_what_it_left() -> None:
    lines = ["def chain(req):", '    v0 = req.args["x"]']
    lines += [f"    v{n} = v{n - 1} + 'a'" for n in range(1, 31)]
    lines += ["    cur.execute(v30)"]
    index = make_index({"a.py": "\n".join(lines) + "\n"})
    candidate = candidate_at("a.py", len(lines))
    capped = BackwardSliceStrategy(depth=20).build(candidate, index, budget=SliceBudget(8192))
    assert capped.recall is not None
    assert capped.recall.defuse_found > capped.recall.defuse_included
    assert capped.truncated
    text = slice_text(capped)
    assert "v30 = v29" in text
    assert "v11 = v10" in text
    assert "v10 = v9" not in text
    deep = BackwardSliceStrategy(depth=40).build(candidate, index, budget=SliceBudget(8192))
    assert deep.recall is not None
    assert deep.recall.defuse_found == deep.recall.defuse_included
    assert 'v0 = req.args["x"]' in slice_text(deep)


def test_a_loop_carried_dependence_terminates() -> None:
    source = """def f(rows):
    acc = ""
    for r in rows:
        acc = acc + r
        r = acc
    cur.execute(acc)
"""
    index = make_index({"a.py": source})
    candidate = candidate_at("a.py", 6)
    text = slice_text(BackwardSliceStrategy().build(candidate, index, budget=BUDGET))
    assert "acc = acc + r" in text
    forward = ForwardSliceStrategy().build(
        taint_candidate(("a.py", 4), ("a.py", 6)), index, budget=BUDGET
    )
    assert "cur.execute(acc)" in slice_text(forward)


def _chain_index() -> tuple[object, object]:
    folder = PATHS / "p12_callee_depth"
    source = (folder / "src" / "app.py").read_text(encoding="utf-8")
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    steps = [tuple(s) for s in meta["between"]]
    candidate = taint_candidate(tuple(meta["source"]), tuple(meta["sink"]), *steps)
    return make_index({"app.py": source}), candidate


@pytest.mark.parametrize(("depth", "cut", "stubbed"), [(0, 1, 3), (1, 2, 2), (2, 3, 1), (3, 4, 0)])
def test_functions_beyond_the_callee_depth_become_stubs(depth: int, cut: int, stubbed: int) -> None:
    index, candidate = _chain_index()
    built = TaintPathStrategy(callee_depth=depth).build(candidate, index, budget=BUDGET)  # type: ignore[arg-type]
    text = slice_text(built)
    functions = ["entry", "first", "second", "third"]
    bodies = [name for name in functions if f"def {name}(" in text.split("# out_of_slice")[0]]
    assert len(bodies) == cut
    assert text.count("# out_of_slice") == stubbed
    assert "third" in bodies


def test_without_a_path_the_taint_strategy_is_not_applicable() -> None:
    index = make_index({"app.py": WORKED})
    with pytest.raises(NotApplicableError) as raised:
        TaintPathStrategy().build(candidate_at("app.py", 7), index, budget=BUDGET)
    assert raised.value.fallback == "no_taint_path"


def test_the_selector_records_why_it_used_a_weaker_strategy() -> None:
    index = make_index({"app.py": WORKED})
    with_path = StrategySelector().build(
        taint_candidate(("app.py", 2), ("app.py", 7)), index, budget=BUDGET
    )
    assert with_path.strategy is SliceStrategy.TAINT_PATH
    assert with_path.fallback_reason is None
    without = StrategySelector().build(candidate_at("app.py", 7), index, budget=BUDGET)
    assert without.strategy is SliceStrategy.BACKWARD_SLICE
    assert without.fallback_reason == "no_taint_path"


def test_the_selector_reaches_the_window_for_code_outside_any_function() -> None:
    source = "import os\ntarget = os.environ['T']\nos.system(target)\n"
    index = make_index({"s.py": source})
    built = StrategySelector().build(candidate_at("s.py", 3), index, budget=BUDGET)
    assert built.strategy in {SliceStrategy.ENCLOSING_FUNCTION, SliceStrategy.SINK_WINDOW}
    assert built.fallback_reason is not None
    assert "os.system(target)" in slice_text(built)


def test_the_selector_honours_the_configured_ceiling() -> None:
    index = make_index({"app.py": WORKED})
    candidate = taint_candidate(("app.py", 2), ("app.py", 7))
    enclosing = StrategySelector(ceiling=SliceStrategy.ENCLOSING_FUNCTION).build(
        candidate, index, budget=BUDGET
    )
    assert enclosing.strategy is SliceStrategy.ENCLOSING_FUNCTION
    with pytest.raises(ValueError, match="selector"):
        StrategySelector(ceiling=SliceStrategy.HOTSPOT)


def test_a_refusal_no_other_strategy_can_cure_is_raised_at_once() -> None:
    index = make_index({"a.py": WORKED}, vendored=("a.py",))
    with pytest.raises(SlicingError) as raised:
        StrategySelector().build(taint_candidate(("a.py", 2), ("a.py", 7)), index, budget=BUDGET)
    assert raised.value.reason == "vendored"


def test_the_selector_is_deterministic() -> None:
    index = make_index({"app.py": WORKED})
    candidate = taint_candidate(("app.py", 2), ("app.py", 7))
    first = StrategySelector().build(candidate, index, budget=BUDGET)
    second = StrategySelector().build(candidate, index, budget=BUDGET)
    assert first.model_dump_json() == second.model_dump_json()


def test_the_window_grows_with_the_budget_and_shrinks_with_locations() -> None:
    small = window_size(SliceBudget(256), 1)
    big = window_size(SliceBudget(2048), 1)
    many = window_size(SliceBudget(2048), 4)
    assert small[0] <= big[0]
    assert many[0] <= big[0]
    assert all(after >= 2 for _, after in (small, big, many))


def test_the_window_covers_each_location_of_a_multi_location_candidate() -> None:
    sources = {"a.py": "def f(x):\n    y = x\n    return y\n", "b.py": "def g(z):\n    return z\n"}
    index = make_index(sources)
    built = SinkWindowStrategy().build(candidate_at("a.py", 3, ("b.py", 2)), index, budget=BUDGET)
    assert {segment.path for segment in built.segments} == {"a.py", "b.py"}


@pytest.mark.parametrize(
    ("folder", "family"),
    [
        ("h01_authorisation", HotspotFamily.AUTHORISATION),
        ("h02_cryptography", HotspotFamily.CRYPTOGRAPHY),
        ("h03_deserialisation", HotspotFamily.DESERIALISATION),
        ("h04_filesystem", HotspotFamily.FILESYSTEM),
        ("h05_database", HotspotFamily.DATABASE),
        ("h06_process", HotspotFamily.PROCESS),
        ("h07_template", HotspotFamily.TEMPLATE),
    ],
)
def test_the_syntactic_hotspots_find_each_family(folder: str, family: HotspotFamily) -> None:
    root = PATHS / folder / "src"
    path = next(p for p in root.rglob("*") if p.is_file()).name
    source = (root / path).read_text(encoding="utf-8")
    index = make_index({path: source})
    found = SyntacticHotspots().hotspots(index.parsed_of(path), index.symbols_of(path))
    assert family in {hotspot.family for hotspot in found}


def test_a_hotspot_slice_is_tagged_for_discovery_and_triage_is_not() -> None:
    folder = PATHS / "h03_deserialisation"
    source = (folder / "src" / "app.py").read_text(encoding="utf-8")
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    index = make_index({"app.py": source})
    candidate = candidate_at("app.py", meta["sink"][1], kind=CandidateKind.HOTSPOT)
    discovery = HotspotStrategy().build(candidate, index, budget=BUDGET)
    assert discovery.purpose is SlicePurpose.DISCOVER
    assert discovery.strategy is SliceStrategy.HOTSPOT
    triage = EnclosingFunctionStrategy().build(candidate, index, budget=BUDGET)
    assert triage.purpose is SlicePurpose.TRIAGE
    assert discovery.id != triage.id
    routed = StrategySelector().build(candidate, index, budget=BUDGET)
    assert routed.purpose is SlicePurpose.DISCOVER


@pytest.mark.parametrize("name", sorted(p.name for p in PATHS.iterdir() if p.name.startswith("p")))
def test_a_path_slice_never_contains_text_outside_the_source_files(name: str) -> None:
    folder = PATHS / name
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    if meta["source"] is None or meta["never_send"]:
        pytest.skip("no path or has never-send")
    sources = {
        p.relative_to(folder / "src").as_posix(): p.read_text(encoding="utf-8")
        for p in (folder / "src").rglob("*")
        if p.is_file()
    }
    index = make_index(sources)
    steps = [tuple(s) for s in meta["between"]]
    candidate = taint_candidate(tuple(meta["source"]), tuple(meta["sink"]), *steps)
    built = TaintPathStrategy(callee_depth=meta["callee_depth"]).build(
        candidate, index, budget=SliceBudget(meta["budget"])
    )
    for segment in built.segments:
        original = sources[segment.path].split("\n")
        for line in segment.text.expose().split("\n"):
            if line.strip() and not line.lstrip().startswith(("#", "//", "pass")):
                assert line in original, (name, line)


# --- properties and the size comparison ------------------------------------------------------


@st.composite
def programs(draw: st.DrawFn) -> tuple[str, int, int, list[int], dict[int, set[int]]]:
    """A straight-line function with random data flow and a sink under nested guards."""
    count = draw(st.integers(min_value=2, max_value=8))
    deps: dict[int, set[int]] = {0: set()}
    lines = ["def f(a):", "    v0 = a"]
    for number in range(1, count):
        chosen = draw(
            st.sets(st.integers(min_value=0, max_value=number - 1), min_size=1, max_size=2)
        )
        deps[number] = chosen
        lines.append(f"    v{number} = " + " + ".join(f"v{n}" for n in sorted(chosen)) + " + a")
    sink_var = draw(st.integers(min_value=0, max_value=count - 1))
    guards = draw(st.lists(st.integers(min_value=0, max_value=count - 1), max_size=3))
    for depth, guard in enumerate(guards):
        lines.append("    " * (depth + 1) + f"if v{guard}:")
    lines.append("    " * (len(guards) + 1) + f"cur.execute(v{sink_var})")
    return "\n".join(lines) + "\n", len(lines), sink_var, guards, deps


def reachable(start: set[int], deps: dict[int, set[int]]) -> set[int]:
    seen: set[int] = set()
    todo = list(start)
    while todo:
        current = todo.pop()
        if current not in seen:
            seen.add(current)
            todo.extend(deps[current])
    return seen


PROPERTY_SETTINGS = settings(max_examples=60, deadline=None)


@PROPERTY_SETTINGS
@given(program=programs())
def test_every_statement_of_a_backward_slice_is_reachable_from_the_sink(
    program: tuple[str, int, int, list[int], dict[int, set[int]]],
) -> None:
    source, sink_line, sink_var, guards, deps = program
    index = make_index({"f.py": source})
    built = BackwardSliceStrategy(depth=40).build(
        candidate_at("f.py", sink_line), index, budget=SliceBudget(8192)
    )
    text = slice_text(built)
    kept = {int(m) for m in re.findall(r"^\s+v(\d+) = ", text, flags=re.MULTILINE)}
    needed = reachable({sink_var}, deps)
    allowed = needed | reachable(set(guards), deps)
    assert needed - {0} <= kept  # nothing the sink depends on is missing
    assert kept <= allowed  # nothing unreachable from the sink or its guards is kept


@PROPERTY_SETTINGS
@given(program=programs())
def test_every_slice_keeps_the_candidates_statement_and_all_its_guards(
    program: tuple[str, int, int, list[int], dict[int, set[int]]],
) -> None:
    source, sink_line, sink_var, guards, _ = program
    index = make_index({"f.py": source})
    plain = candidate_at("f.py", sink_line)
    with_path = taint_candidate(("f.py", 2), ("f.py", sink_line))
    for strategy, candidate in (
        (BackwardSliceStrategy(), plain),
        (SinkWindowStrategy(), plain),
        (TaintPathStrategy(), with_path),
        (EnclosingFunctionStrategy(), plain),
    ):
        text = slice_text(strategy.build(candidate, index, budget=SliceBudget(8192)))
        assert f"cur.execute(v{sink_var})" in text
        for guard in guards:
            assert f"if v{guard}:" in text


def test_the_size_of_each_strategy_for_the_same_candidate(
    record_property: Callable[[str, object], None],
) -> None:
    index = make_index({"app.py": WORKED})
    candidate = taint_candidate(("app.py", 2), ("app.py", 7))
    sizes = {
        strategy.name.value: strategy.build(candidate, index, budget=BUDGET).token_estimate
        for strategy in (
            TaintPathStrategy(),
            BackwardSliceStrategy(),
            ForwardSliceStrategy(),
            SinkWindowStrategy(),
            EnclosingFunctionStrategy(),
        )
    }
    record_property("slice_size_tokens", sizes)  # shown in the junit report
    assert sizes["taint_path"] < sizes["enclosing_function"]
    assert sizes["backward_slice"] < sizes["enclosing_function"]
    assert sizes["forward_slice"] < sizes["enclosing_function"]
    assert sizes["taint_path"] <= sizes["sink_window"]


def test_through_the_selector_a_path_gives_a_smaller_slice_than_none() -> None:
    index = make_index({"app.py": WORKED})
    candidate = taint_candidate(("app.py", 2), ("app.py", 7))
    with_path = StrategySelector().build(candidate, index, budget=BUDGET)
    without = StrategySelector(ceiling=SliceStrategy.ENCLOSING_FUNCTION).build(
        candidate, index, budget=BUDGET
    )
    assert with_path.token_estimate < without.token_estimate


def test_a_step_in_a_never_send_file_is_withheld_and_counted() -> None:
    folder = PATHS / "p06_never_send_step"
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    sources = {
        p.relative_to(folder / "src").as_posix(): p.read_text(encoding="utf-8")
        for p in (folder / "src").rglob("*")
        if p.is_file()
    }
    never = never_send_matcher(
        Settings.model_validate({"privacy": {"never_send": meta["never_send"]}})
    )
    index = make_index(sources, never_send=never)
    steps = [tuple(s) for s in meta["between"]]
    candidate = taint_candidate(tuple(meta["source"]), tuple(meta["sink"]), *steps)
    built = TaintPathStrategy().build(candidate, index, budget=BUDGET)
    assert built.recall is not None
    assert built.recall.path_steps_withheld == 1
    assert built.recall.path_steps_included == built.recall.path_steps_total - 1
    assert "secrets_store" not in "".join(s.path for s in built.segments)
