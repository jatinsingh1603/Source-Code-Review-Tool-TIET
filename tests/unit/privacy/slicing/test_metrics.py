"""Disclosure measurement (E11-04): per-slice figures, the interval union, call edges, rows."""

import itertools
import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import (
    CodeRegion,
    CodeSlice,
    RawCode,
    SegmentRole,
    SliceSegment,
    SliceStrategy,
    Stub,
    StubReason,
)
from codekavach.core.models.ids import CandidateId
from codekavach.privacy.slicing.metrics import IntervalSet, ScanDisclosure, measure
from tests.support.factories import CANDIDATE_ID, SLICE_ID
from tests.support.slicing import candidate_id_n, make_index

FILE_A = "".join(f"def f{n}(x):\n    return x + {n}\n\n\n" for n in range(1, 51))  # 200 lines
FILE_B = "def g(x):\n    return x\n"
INDEX = make_index({"a.py": FILE_A, "b.py": FILE_B})
OTHER_ID = candidate_id_n(0)


def seg(path: str, start: int, end: int, role: SegmentRole = SegmentRole.CONTEXT) -> SliceSegment:
    return SliceSegment(
        path=path,
        region=CodeRegion(start_line=start, end_line=end),
        text=RawCode("\n".join("x" for _ in range(start, end + 1))),
        role=role,
    )


def make(
    *segments: SliceSegment, stubs: tuple[Stub, ...] = (), candidate: str | None = None
) -> CodeSlice:
    if not any(s.role is SegmentRole.PRIMARY for s in segments):
        segments = (segments[0].evolve(role=SegmentRole.PRIMARY), *segments[1:])
    return CodeSlice(
        id=SLICE_ID,
        candidate_id=CandidateId(candidate) if candidate else CANDIDATE_ID,
        language=INDEX.parsed_of("a.py").language,
        strategy=SliceStrategy.ENCLOSING_FUNCTION,
        segments=segments,
        stubs=stubs,
        token_estimate=10 * sum(s.region.line_count for s in segments),
    )


def stub(symbol: str, path: str | None = None) -> Stub:
    return Stub(
        symbol=symbol,
        signature=RawCode(f"def {symbol}(): ..."),
        reason=StubReason.CROSS_FILE_CALLEE,
        path=path,
    )


# --- measure ---------------------------------------------------------------------------------


def test_measure_a_single_segment_slice() -> None:
    found = measure(make(seg("a.py", 1, 4)), INDEX)
    assert (found.lines, found.tokens, found.files, found.functions) == (4, 40, 1, 1)
    assert found.file_fraction == pytest.approx(4 / 200)
    assert found.repo_fraction == pytest.approx(4 / INDEX.total_lines)
    assert (found.stub_count, found.truncated, found.strategy) == (0, False, "enclosing_function")


def test_measure_a_multi_segment_slice_counts_each_function_once() -> None:
    found = measure(make(seg("a.py", 1, 2), seg("a.py", 3, 3), seg("a.py", 5, 6)), INDEX)
    assert found.lines == 5
    assert found.functions == 2  # f1 (lines 1-2), f2 (lines 5-6); line 3 is a blank gap


def test_measure_a_multi_file_slice() -> None:
    found = measure(make(seg("a.py", 1, 2), seg("b.py", 1, 2)), INDEX)
    assert (found.files, found.lines, found.functions) == (2, 4, 2)
    assert found.file_fraction == pytest.approx(4 / (200 + 2))


def test_measure_counts_stubs_and_truncation() -> None:
    sliced = make(seg("a.py", 1, 2), stubs=(stub("helper"),))
    assert measure(sliced, INDEX).stub_count == 1
    assert measure(sliced.evolve(truncated=True), INDEX).truncated is True


# --- the interval set ------------------------------------------------------------------------


def test_the_interval_set_merges_adjacent_nested_and_overlapping_intervals() -> None:
    covered = IntervalSet()
    assert covered.add(10, 19) == 10
    assert covered.add(20, 29) == 10  # adjacent
    assert covered.intervals() == ((10, 29),)
    assert covered.add(12, 15) == 0  # nested
    assert covered.add(25, 40) == 11  # overlapping the end
    assert covered.add(1, 3) == 3
    assert covered.add(5, 8) == 4
    assert covered.intervals() == ((1, 3), (5, 8), (10, 40))
    assert covered.add(1, 50) == 50 - (3 + 4 + 31)
    assert covered.intervals() == ((1, 50),)
    assert covered.total == 50


def test_the_interval_set_reports_covered_lines_without_changing() -> None:
    covered = IntervalSet()
    covered.add(10, 20)
    covered.add(30, 40)
    assert covered.covered(1, 9) == 0
    assert covered.covered(15, 35) == 6 + 6
    assert covered.covered(10, 40) == 22
    assert covered.total == 22


def test_an_interval_must_not_end_before_it_starts() -> None:
    with pytest.raises(ValueError, match="ends at or after"):
        IntervalSet().add(5, 4)


@settings(max_examples=100, deadline=None)
@given(st.lists(st.tuples(st.integers(1, 80), st.integers(0, 15)), max_size=12))
def test_the_interval_set_equals_the_set_of_covered_lines(raw: list[tuple[int, int]]) -> None:
    covered = IntervalSet()
    lines: set[int] = set()
    for start, length in raw:
        end = start + length
        gained = covered.add(start, end)
        before = len(lines)
        lines.update(range(start, end + 1))
        assert gained == len(lines) - before
    assert covered.total == len(lines)
    spans = covered.intervals()
    assert all(a_end + 1 < b_start for (_, a_end), (b_start, _) in itertools.pairwise(spans))


# --- the scan record: the union -------------------------------------------------------------


def test_the_worked_example_is_a_hundred_lines_and_one_percent_not_two_hundred_twenty() -> None:
    index = make_index({"big.py": "x = 1\n" * 10_000})
    record = ScanDisclosure(repo_lines=10_000)
    function = (seg("big.py", 100, 159),)
    for number in range(3):  # three candidates in one 60-line function
        record.record(make(*function, candidate=candidate_id_n(number + 2)), index)
    record.record(make(seg("big.py", 400, 439)), index)  # one in a 40-line function
    assert record.union_lines == 100
    assert record.repo_pct == pytest.approx(1.0)
    assert record.lines_total == 220  # the activity count, never divided by the repository


def test_two_overlapping_slices_of_one_function_count_once() -> None:
    record = ScanDisclosure.for_index(INDEX)
    record.record(make(seg("a.py", 1, 10)), INDEX)
    record.record(make(seg("a.py", 5, 14)), INDEX)
    assert record.union_lines == 14
    assert record.lines_total == 20
    assert record.files == 1


def test_the_figures_do_not_depend_on_the_order_of_recording() -> None:
    slices = [
        make(seg("a.py", 1, 8)),
        make(seg("a.py", 5, 14), seg("b.py", 1, 2)),
        make(seg("a.py", 40, 44), stubs=(stub("helper"),)),
    ]
    rows = set()
    for order in itertools.permutations(slices):
        record = ScanDisclosure.for_index(INDEX)
        for item in order:
            record.record(item, INDEX)
        rows.add(record.as_attestation_rows())
    assert len(rows) == 1


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.tuples(st.integers(1, 190), st.integers(0, 9)),
        min_size=1,
        max_size=8,
    )
)
def test_the_union_is_at_most_the_sum_and_equal_when_nothing_overlaps(
    raw: list[tuple[int, int]],
) -> None:
    record = ScanDisclosure.for_index(INDEX)
    spans = [(start, start + length) for start, length in raw]
    for start, end in spans:
        record.record(make(seg("a.py", start, end)), INDEX)
    total = sum(end - start + 1 for start, end in spans)
    assert record.union_lines <= record.lines_total == total
    disjoint = all(
        a_end < b_start or b_end < a_start
        for (a_start, a_end), (b_start, b_end) in itertools.combinations(spans, 2)
    )
    if disjoint:
        assert record.union_lines == total


def test_would_reach_counts_only_the_lines_not_yet_disclosed() -> None:
    record = ScanDisclosure(repo_lines=100)
    record.record(make(seg("a.py", 1, 10)), INDEX)
    assert record.would_reach_pct(make(seg("a.py", 5, 14))) == pytest.approx(14.0)
    assert record.would_reach_pct(make(seg("b.py", 1, 2))) == pytest.approx(12.0)
    assert record.union_lines == 10  # nothing was recorded by asking


def test_a_scan_record_needs_a_repository() -> None:
    with pytest.raises(ValueError, match="at least one line"):
        ScanDisclosure(repo_lines=0)


# --- call edges ------------------------------------------------------------------------------


def test_functions_that_appear_together_form_edges_and_repeats_count_once() -> None:
    record = ScanDisclosure.for_index(INDEX)
    record.record(make(seg("a.py", 1, 2), seg("a.py", 5, 6)), INDEX)  # f1 and f2 together
    assert (record.functions, record.call_edges) == (2, 1)
    record.record(make(seg("a.py", 1, 2), seg("a.py", 5, 6)), INDEX)  # the same pair again
    assert record.call_edges == 1
    record.record(make(seg("a.py", 1, 2), seg("a.py", 9, 10)), INDEX)  # f1 and f3
    assert (record.functions, record.call_edges) == (3, 2)


def test_a_caller_and_its_stub_form_an_edge() -> None:
    record = ScanDisclosure.for_index(INDEX)
    record.record(make(seg("a.py", 1, 2), stubs=(stub("run_query", "db.py"),)), INDEX)
    assert (record.functions, record.call_edges) == (1, 1)
    record.record(make(seg("a.py", 1, 2), stubs=(stub("run_query", "db.py"),)), INDEX)
    assert record.call_edges == 1
    record.record(make(seg("a.py", 1, 2), stubs=(stub("other", "db.py"),)), INDEX)
    assert record.call_edges == 2


# --- rounds and rows ---------------------------------------------------------------------------


def test_rounds_are_counted_per_candidate() -> None:
    record = ScanDisclosure.for_index(INDEX)
    record.record(make(seg("a.py", 1, 2)), INDEX)
    record.record(make(seg("a.py", 5, 6)), INDEX, expansion=True)
    record.record(make(seg("a.py", 9, 10), candidate=OTHER_ID), INDEX, expansion=True)
    record.record(make(seg("a.py", 13, 14)), INDEX, expansion=True)
    assert record.rounds_used(CANDIDATE_ID) == 2
    assert record.rounds_used(OTHER_ID) == 1
    assert record.rounds_used(candidate_id_n(1)) == 0
    assert record.expansions == 3


def test_attestation_rows_are_counts_and_fractions_with_no_path_or_name() -> None:
    record = ScanDisclosure.for_index(INDEX)
    record.record(make(seg("a.py", 1, 2), stubs=(stub("secret_helper", "b.py"),)), INDEX)
    rows = record.as_attestation_rows()
    flat = " ".join(f"{label} {value}" for label, value in rows)
    assert "a.py" not in flat and "b.py" not in flat and "secret_helper" not in flat
    assert dict(rows)["lines_disclosed"] == "2"
    assert dict(rows)["strategy_enclosing_function"] == "1"
    assert all(re.fullmatch(r"[0-9]+(\.[0-9]{2})?", value) for label, value in rows)
