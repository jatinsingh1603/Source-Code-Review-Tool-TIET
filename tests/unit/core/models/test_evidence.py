from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import DataClassification, Language
from codekavach.core.models.enums import EvidenceRole
from codekavach.core.models.evidence import Evidence, HighlightRange, SnippetLine
from codekavach.core.models.location import Location
from codekavach.core.models.text import RawCode, split_lines

CANARY = "CANARY_9f3a"
FORM_FEED = "\x0c"
LINE_SEPARATOR = chr(0x2028)
STATEMENT = '        cur.execute("SELECT * FROM accounts WHERE owner = \'" + owner + "\'")'


def loc(
    start: int, end: int | None = None, c1: int | None = None, c2: int | None = None
) -> Location:
    return Location(
        path="src/bank/accounts.py",
        start_line=start,
        end_line=end if end is not None else start,
        start_col=c1,
        end_col=c2,
    )


def fixture_200() -> RawCode:
    lines = [f"line_{n} = {n}" for n in range(1, 201)]
    lines[85] = "    def find_by_owner(self, owner):"
    lines[86] = "        cur = self.conn.cursor()"
    lines[87] = STATEMENT
    lines[88] = "        return cur.fetchall()"
    return RawCode("\n".join(lines) + "\n")


def build(source: str | RawCode, location: Location, **kwargs: Any) -> Evidence:
    raw = source if isinstance(source, RawCode) else RawCode(source)
    return Evidence.from_source(raw, location, language=Language.PYTHON, **kwargs)


def test_two_hundred_line_fixture() -> None:
    evidence = build(fixture_200(), loc(88), context_lines=2)
    assert [line.number for line in evidence.lines] == [86, 87, 88, 89, 90]
    assert evidence.highlights == (HighlightRange(line=88, start_col=9, end_col=76),)


def test_worked_example() -> None:
    assert len(STATEMENT) == 75
    source = "\n".join(
        ["x"] * 85
        + [
            "    def find_by_owner(self, owner):",
            "        cur = self.conn.cursor()",
            STATEMENT,
            "        return cur.fetchall()",
        ]
    )
    evidence = build(source, loc(88), context_lines=2)
    assert [line.number for line in evidence.lines] == [86, 87, 88, 89]
    assert evidence.highlights[0].start_col == 9
    assert evidence.highlights[0].end_col == 76


def test_location_at_first_line() -> None:
    evidence = build("a = 1\nb = 2\nc = 3\n", loc(1), context_lines=3)
    assert [line.number for line in evidence.lines] == [1, 2, 3]


def test_location_at_last_line_without_trailing_newline() -> None:
    evidence = build("a = 1\nb = 2\nc = 3", loc(3))
    assert evidence.lines[-1].number == 3
    assert evidence.lines[-1].text == RawCode("c = 3")


def test_crlf_file() -> None:
    evidence = build("a = 1\r\nb = 2\r\nc = 3\r\n", loc(2))
    assert all("\r" not in line.text.expose() for line in evidence.lines)


def test_form_feed_and_line_separator_do_not_split() -> None:
    source = f"a = 1\nb{FORM_FEED}c{LINE_SEPARATOR}d = 2\ntarget = 3\n"
    evidence = build(source, loc(3))
    assert evidence.highlights[0].line == 3
    assert evidence.lines[1].text == RawCode(f"b{FORM_FEED}c{LINE_SEPARATOR}d = 2")


def test_long_region_is_clipped() -> None:
    source = "".join(f"v{n} = {n}\n" for n in range(1, 151))
    evidence = build(source, loc(20, 119), max_lines=40)
    assert evidence.clipped
    assert len(evidence.lines) == 40
    assert evidence.lines[0].number == 17


def test_very_long_line_is_truncated() -> None:
    evidence = build("x" * 100_000 + "\n", loc(1), max_line_length=400)
    line = evidence.lines[0]
    assert line.truncated
    assert len(line.text) == 400
    assert evidence.highlights == (HighlightRange(line=1, start_col=1, end_col=401),)


def test_highlight_starting_beyond_cut_is_dropped() -> None:
    evidence = build("y" * 1000 + "\n", loc(1, 1, 500, 510), max_line_length=400)
    assert evidence.highlights == ()


def test_empty_line_inside_region_gets_no_highlight() -> None:
    evidence = build("a = 1\n\n   \nb = 2\n", loc(1, 4))
    assert [h.line for h in evidence.highlights] == [1, 4]


def test_tab_indented_line() -> None:
    evidence = build("\tvalue = 1\n", loc(1))
    assert evidence.highlights[0].start_col == 2
    assert evidence.lines[0].text == RawCode("\tvalue = 1")


def test_end_col_beyond_line_is_clamped() -> None:
    evidence = build("abc\n", loc(1, 1, 2, 50))
    assert evidence.highlights == (HighlightRange(line=1, start_col=2, end_col=4),)


def test_zero_width_location_has_no_highlight() -> None:
    assert build("abc\n", loc(1, 1, 2, 2)).highlights == ()


def test_multi_line_with_columns() -> None:
    evidence = build("  first line\n  middle\n  last part\n", loc(1, 3, 5, 6))
    assert evidence.highlights == (
        HighlightRange(line=1, start_col=5, end_col=13),
        HighlightRange(line=2, start_col=3, end_col=9),
        HighlightRange(line=3, start_col=3, end_col=6),
    )


def test_location_beyond_file_rejected_without_source_text() -> None:
    with pytest.raises(ValueError, match="line 5") as info:
        build(f"{CANARY}\n", loc(5))
    assert CANARY not in str(info.value)
    assert "1 lines" in str(info.value)


def test_max_lines_must_exceed_context() -> None:
    with pytest.raises(ValueError, match="max_lines"):
        build("a\n", loc(1), context_lines=3, max_lines=3)


# validation


def line(number: int, text: str = "code") -> SnippetLine:
    return SnippetLine(number=number, text=RawCode(text))


def evidence(**overrides: Any) -> Evidence:
    fields: dict[str, Any] = {
        "location": loc(2),
        "language": Language.PYTHON,
        "lines": (line(1), line(2), line(3)),
    }
    fields.update(overrides)
    return Evidence.model_validate(fields)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"lines": (line(1), line(3))}, "contiguous"),
        ({"highlights": (HighlightRange(line=9, start_col=1, end_col=2),)}, "outside"),
        (
            {
                "highlights": (
                    HighlightRange(line=2, start_col=1, end_col=4),
                    HighlightRange(line=2, start_col=3, end_col=5),
                )
            },
            "overlap",
        ),
        (
            {
                "highlights": (
                    HighlightRange(line=3, start_col=1, end_col=2),
                    HighlightRange(line=2, start_col=1, end_col=2),
                )
            },
            "sorted",
        ),
        ({"highlights": (HighlightRange(line=2, start_col=1, end_col=9),)}, "beyond the end"),
        ({"location": loc(2, 5)}, "beyond an unclipped"),
        ({"location": loc(7)}, "start line"),
    ],
)
def test_invalid_evidence(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        evidence(**overrides)


def test_clipped_allows_location_beyond_snippet() -> None:
    assert evidence(location=loc(2, 9), clipped=True).clipped


def test_highlight_columns() -> None:
    with pytest.raises(ValidationError):
        HighlightRange(line=1, start_col=3, end_col=3)
    with pytest.raises(ValidationError):
        HighlightRange(line=1, start_col=0, end_col=3)


def test_snippet_line_rejects_line_break() -> None:
    with pytest.raises(ValidationError):
        SnippetLine(number=1, text=RawCode("a\nb"))


def test_masked_and_caption() -> None:
    assert evidence(masked=True).masked
    assert evidence(caption="x" * 300).caption == "x" * 300
    with pytest.raises(ValidationError):
        evidence(caption="x" * 301)


def test_classification_round_trip_and_repr() -> None:
    assert Evidence.DATA_CLASSIFICATION is DataClassification.RAW
    assert SnippetLine.DATA_CLASSIFICATION is DataClassification.RAW
    assert HighlightRange.DATA_CLASSIFICATION is DataClassification.METADATA
    built = build(f"key = '{CANARY}'\n", loc(1), role=EvidenceRole.SINK, caption="sink")
    assert Evidence.model_validate_json(built.model_dump_json()) == built
    assert CANARY not in repr(built)


# property

_line_text = st.text(
    alphabet=st.characters(codec="utf-8", blacklist_characters="\n\r"), max_size=60
) | st.sampled_from(["\tindented", f"a{FORM_FEED}b", f"c{LINE_SEPARATOR}d", "", "   "])


@st.composite
def cases(draw: st.DrawFn) -> tuple[list[str], Location]:
    lines = draw(st.lists(_line_text, min_size=1, max_size=300))
    start = draw(st.integers(1, len(lines)))
    end = draw(st.integers(start, len(lines)))
    if draw(st.booleans()):
        c1 = draw(st.integers(1, 80))
        c2 = draw(st.integers(c1 if start == end else 1, 90))
        return lines, loc(start, end, c1, c2)
    return lines, loc(start, end)


@given(cases(), st.integers(0, 5), st.integers(6, 50), st.integers(1, 80))
def test_from_source_never_raises_for_valid_locations(
    case: tuple[list[str], Location], context: int, max_lines: int, max_len: int
) -> None:
    lines, location = case
    source = "\n".join(lines) + "\n"
    evidence = build(
        source, location, context_lines=context, max_lines=max_lines, max_line_length=max_len
    )
    reference = split_lines(source)
    for snippet_line in evidence.lines:
        assert snippet_line.text.expose() == reference[snippet_line.number - 1][:max_len]
