"""The layout of a payload and its line map (E09-05).

The worked example of the issue: ``accounts.py`` lines 40 to 52 and 88 to 91, with a marker line
between, give two entries, and payload line 16 is file line 89 of segment 1.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import (
    CodeRegion,
    Language,
    PrivacyLevel,
    RawCode,
    SanitisedPayload,
    SanitisedText,
    SliceSegment,
)
from codekavach.core.models.text import split_lines
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.linemap import LineKind, LineMapBuilder, layout_of
from codekavach.privacy.slicing.assemble import assemble, numbered_labels
from tests.support.factories import CANDIDATE_ID, SLICE_ID
from tests.support.payload import segment, slice_of, stub

FIRST = [f"line_{n}" for n in range(40, 53)]
SECOND = [f"line_{n}" for n in range(88, 92)]


def two_segments() -> object:
    return slice_of(segment("accounts.py", 40, FIRST), segment("accounts.py", 88, SECOND))


def payload_for(slice_, text: str, framed: bool = True) -> SanitisedPayload:  # type: ignore[no-untyped-def]
    return SanitisedPayload.build(
        candidate_id=CANDIDATE_ID,
        slice_id=SLICE_ID,
        text=SanitisedText(text),
        level=PrivacyLevel.L3,
        line_map=LineMapBuilder.build(slice_, text, framed=framed),
    )


def test_the_worked_example_has_two_entries_and_line_16_is_file_line_89() -> None:
    slice_ = two_segments()
    text = layout_of(slice_, PrivacyLevel.L3, framed=False).text  # type: ignore[arg-type]
    entries = LineMapBuilder.build(slice_, text, framed=False)  # type: ignore[arg-type]
    assert [
        (e.payload_start_line, e.payload_end_line, e.segment_index, e.file_start_line)
        for e in entries
    ] == [(1, 13, 0, 40), (15, 18, 1, 88)]
    payload = payload_for(slice_, text, framed=False)
    assert payload.map_line(16) == (1, 89)
    assert payload.map_line(14) is None  # the elision marker


def test_the_framed_layout_has_a_header_and_a_label_that_map_to_nothing() -> None:
    slice_ = two_segments()
    layout = layout_of(slice_, PrivacyLevel.L3)  # type: ignore[arg-type]
    kinds = [line.kind for line in layout.lines]
    assert kinds[:2] == [LineKind.HEADER, LineKind.LABEL]
    assert layout.lines[0].text == "# codekavach payload L3"
    assert layout.lines[1].text == "# file_1"
    payload = payload_for(slice_, layout.text)
    assert payload.map_line(1) is None
    assert payload.map_line(2) is None
    assert payload.map_line(3) == (0, 40)
    assert payload.map_line(15) == (0, 52)
    assert payload.map_line(16) is None
    assert payload.map_line(18) == (1, 89)


def test_stub_lines_and_the_blank_line_before_them_are_not_covered() -> None:
    slice_ = slice_of(
        segment("a.py", 1, ["def f(x):", "    return g(x)"]),
        stubs=[stub("g", "def g(y): ...\n# returns value; derived: syntactic")],
    )
    layout = layout_of(slice_, PrivacyLevel.L3)
    assert [line.kind for line in layout.lines][-3:] == [
        LineKind.SEPARATOR,
        LineKind.STUB,
        LineKind.STUB,
    ]
    payload = payload_for(slice_, layout.text)
    covered = [n for n in range(1, len(layout.lines) + 1) if payload.map_line(n) is not None]
    assert covered == [3, 4]


def test_adjacent_segments_give_two_entries_and_no_marker() -> None:
    slice_ = slice_of(segment("a.py", 1, ["x = 1", "y = 2"]), segment("a.py", 3, ["z = 3"]))
    layout = layout_of(slice_, PrivacyLevel.L3)
    assert LineKind.ELISION not in {line.kind for line in layout.lines}
    entries = LineMapBuilder.build(slice_, layout.text)
    assert [(e.payload_start_line, e.payload_end_line, e.segment_index) for e in entries] == [
        (3, 4, 0),
        (5, 5, 1),
    ]


def test_two_files_are_separated_by_a_blank_line_and_labelled_in_path_order() -> None:
    slice_ = slice_of(segment("b.py", 1, ["b = 1"]), segment("a.py", 1, ["a = 1"]))
    layout = layout_of(slice_, PrivacyLevel.L3)
    assert [line.text for line in layout.lines] == [
        "# codekavach payload L3",
        "# file_1",
        "a = 1",
        "",
        "# file_2",
        "b = 1",
    ]
    assert [e.segment_index for e in LineMapBuilder.build(slice_, layout.text)] == [1, 0]


def test_the_layout_is_the_text_of_the_slicers_assembly_under_a_header() -> None:
    slice_ = slice_of(
        segment("a.py", 1, ["def f(x):", "    return g(x)"]),
        segment("a.py", 9, ["def h():", "    pass"]),
        segment("b.py", 3, ["v = 1"]),
        stubs=[stub("g", "def g(y): ...", path="c.py", line=1)],
    )
    paths = [s.path for s in slice_.segments]
    assembled = assemble(
        slice_.segments, slice_.stubs, language=Language.PYTHON, labels=numbered_labels(paths)
    )
    assert layout_of(slice_, PrivacyLevel.L3).text == f"# codekavach payload L3\n{assembled}\n"


def test_a_javascript_layout_uses_the_slash_comment() -> None:
    slice_ = slice_of(segment("a.js", 1, ["f();"]), language=Language.JAVASCRIPT)
    assert layout_of(slice_, PrivacyLevel.L2).lines[0].text == "// codekavach payload L2"


def test_a_text_with_another_line_count_is_refused() -> None:
    slice_ = two_segments()
    with pytest.raises(PseudonymError, match="line structure"):
        LineMapBuilder.build(slice_, "one line\n")  # type: ignore[arg-type]


def test_a_final_blank_line_of_a_segment_is_kept() -> None:
    blank_end = SliceSegment(
        path="a.py", region=CodeRegion(start_line=1, end_line=2), text=RawCode("x = 1\n\n")
    )
    slice_ = slice_of(blank_end)
    layout = layout_of(slice_, PrivacyLevel.L3)
    assert len(split_lines(layout.text)) == len(layout.lines) == 4


def test_the_layout_does_not_depend_on_the_order_of_the_files() -> None:
    a = segment("a.py", 1, ["x = 1"])
    b = segment("a.py", 9, ["y = 2"])
    c = segment("b.py", 1, ["z = 3"])
    first = layout_of(slice_of(a, b, c), PrivacyLevel.L3).text
    second = layout_of(slice_of(c, a, b), PrivacyLevel.L3).text
    assert first == second


@settings(max_examples=60, deadline=None)
@given(
    sizes=st.lists(st.integers(1, 6), min_size=1, max_size=5),
    gaps=st.lists(st.integers(0, 3), min_size=5, max_size=5),
    with_stub=st.booleans(),
)
def test_map_line_inverts_the_map_for_every_covered_line(
    sizes: list[int], gaps: list[int], with_stub: bool
) -> None:
    segments = []
    start = 1
    for size, gap in zip(sizes, gaps, strict=False):
        segments.append(segment("m.py", start, [f"v{start + n} = {n}" for n in range(size)]))
        start += size + gap
    slice_ = slice_of(*segments, stubs=[stub("g", "def g(): ...")] if with_stub else [])
    layout = layout_of(slice_, PrivacyLevel.L3)
    payload = payload_for(slice_, layout.text)
    for number, line in enumerate(layout.lines, start=1):
        mapped = payload.map_line(number)
        if line.kind is LineKind.SEGMENT:
            assert mapped == (line.segment_index, line.file_line)
            segment_ = slice_.segments[line.segment_index]  # type: ignore[index]
            assert split_lines(segment_.text.expose())[
                (mapped[1] - segment_.region.start_line)
            ] == (line.text)
        else:
            assert mapped is None
