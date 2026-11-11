"""The taint lattice and the per-point state (E17-02)."""

from codekavach.analysis.taint.ir import Place
from codekavach.analysis.taint.state import (
    MAX_ORIGINS,
    Fact,
    Step,
    Tainted,
    TaintState,
    Unknown,
    Untainted,
    join,
    merge,
    with_cleared,
    with_guard,
    with_step,
)
from codekavach.core.models import Location, TaintRole


def step(line: int, role: TaintRole = TaintRole.PROPAGATOR, note: str | None = None) -> Step:
    return Step(role, Location(path="a.py", start_line=line, end_line=line), note)


def fact(*lines: int, labels: tuple[str, ...] = ("http_param",)) -> Fact:
    chain = tuple(
        step(line, TaintRole.SOURCE if i == 0 else TaintRole.PROPAGATOR)
        for i, line in enumerate(lines)
    )
    return Fact(Tainted(frozenset(labels)), chain)


def test_join_is_a_union_of_labels() -> None:
    assert join(Untainted(), Untainted()) == Untainted()
    assert join(Untainted(), Tainted(frozenset({"a"}))) == Tainted(frozenset({"a"}))
    assert join(Tainted(frozenset({"a"})), Tainted(frozenset({"b"}))) == Tainted(
        frozenset({"a", "b"})
    )


def test_unknown_absorbs_tainted_and_is_never_untainted() -> None:
    assert join(Unknown(), Tainted(frozenset({"a"}))) == Unknown(frozenset({"a"}))
    assert join(Tainted(frozenset({"a"})), Unknown(frozenset({"b"}))) == Unknown(
        frozenset({"a", "b"})
    )
    assert join(Unknown(), Untainted()) == Unknown()
    assert join(Untainted(), Unknown()) == Unknown()


def test_merge_keeps_the_shorter_chain_and_the_weaker_clearing_per_origin() -> None:
    long = Fact(Tainted(frozenset({"a"})), fact(1, 2, 3).chain, frozenset({"sql"}))
    short = Fact(Tainted(frozenset({"a"})), fact(1, 3).chain, frozenset())
    merged = merge({"o": long}, {"o": short})
    assert len(merged["o"].chain) == 2
    assert merged["o"].cleared == frozenset()


def test_merge_keeps_different_origins_apart_and_bounds_them() -> None:
    parts = [{f"o{n:02d}": fact(1, n + 2)} for n in range(MAX_ORIGINS + 5)]
    merged = merge(*parts)
    assert len(merged) == MAX_ORIGINS
    assert list(merged) == sorted(merged)


def test_a_step_at_the_same_location_is_not_repeated_but_a_sanitiser_is_kept() -> None:
    facts = {"o": fact(4)}
    again = with_step(facts, step(4, note="assign"))
    assert len(again["o"].chain) == 1
    sanitised = with_step(
        facts, Step(TaintRole.SANITISER, step(4).location, "sanitiser x", frozenset({"html"}))
    )
    assert len(sanitised["o"].chain) == 2
    assert sanitised["o"].cleared == frozenset({"html"})


def test_an_uncertain_step_turns_values_into_unknown() -> None:
    result = with_step({"o": fact(1)}, step(2), uncertain=True)
    assert result["o"].uncertain and result["o"].labels == frozenset({"http_param"})


def test_clearing_and_guards_are_recorded_on_the_facts() -> None:
    facts = with_guard(with_cleared({"o": fact(1)}, frozenset({"sql"})), 7)
    assert facts["o"].cleared == frozenset({"sql"})
    assert facts["o"].guards == (7,)
    assert with_guard(facts, 7)["o"].guards == (7,)


def test_a_strong_write_replaces_and_kills_paths_below_it() -> None:
    state = TaintState()
    state.write(Place(base="o", steps=(".p",)), {"x": fact(1)})
    assert state.read(Place(base="o"))
    state.write(Place(base="o"), {})
    assert state.read(Place(base="o", steps=(".p",))) == {}


def test_a_weak_write_keeps_earlier_facts() -> None:
    state = TaintState()
    state.write(Place(base="d"), {"x": fact(1)})
    state.write(Place(base="d", steps=("[*]",)), {"y": fact(2)})
    assert set(state.read(Place(base="d"))) == {"x", "y"}


def test_reads_see_related_paths_only() -> None:
    state = TaintState()
    state.write(Place(base="o", steps=(".p",)), {"x": fact(1)})
    assert state.read(Place(base="o"))
    assert state.read(Place(base="o", steps=(".p", ".q")))
    assert state.read(Place(base="o", steps=(".other",))) == {}


def test_join_of_states_and_equality() -> None:
    left, right = TaintState(), TaintState()
    left.write(Place(base="a"), {"x": fact(1)})
    right.write(Place(base="b"), {"y": fact(2)})
    joined = left.join(right)
    assert set(joined.entries) == {"a", "b"}
    assert joined == right.join(left)
    assert left != joined
