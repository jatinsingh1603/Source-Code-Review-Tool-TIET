from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import Language
from codekavach.core.models.evidence import Evidence, HighlightRange, SnippetLine
from codekavach.core.models.location import Location
from codekavach.core.models.text import RawCode
from tests.support.golden import assert_matches_golden
from tests.unit.core.models.test_evidence import STATEMENT, build, cases, fixture_200, loc

GOLDEN = Path(__file__).parent / "golden"
WORKED = (
    "   86 |     def find_by_owner(self, owner):\n"
    "   87 |         cur = self.conn.cursor()\n"
    f">  88 | {STATEMENT}\n"
    "      |         " + "^" * 67 + "\n"
    "   89 |         return cur.fetchall()\n"
)


def worked_example() -> Evidence:
    source = "\n".join(
        ["x"] * 85
        + [
            "    def find_by_owner(self, owner):",
            "        cur = self.conn.cursor()",
            STATEMENT,
            "        return cur.fetchall()",
        ]
    )
    return build(source, loc(88), context_lines=2)


def manual(texts: list[str], first: int, highlights: list[tuple[int, int, int]]) -> Evidence:
    return Evidence(
        location=loc(first),
        language=Language.PYTHON,
        lines=tuple(
            SnippetLine(number=first + index, text=RawCode(text))
            for index, text in enumerate(texts)
        ),
        highlights=tuple(HighlightRange(line=a, start_col=b, end_col=c) for a, b, c in highlights),
    )


def test_worked_example_exact() -> None:
    assert worked_example().render_text() == WORKED


def golden_cases() -> dict[str, Evidence]:
    tabbed = "def f():\n\tif x:\n\t\treturn eval(x)\n"
    long_line = "a = 1\nquery = '" + "q" * 60 + "'\nb = 2\n"
    wide = "\n".join(f"v{n} = {n}" for n in range(1, 12_346)) + "\n"
    return {
        "evidence_single_line": worked_example(),
        "evidence_multi_line": build(fixture_200(), loc(87, 88, 15, 20), context_lines=1),
        "evidence_truncated_line": build(long_line, loc(2, 2, 3, 70), max_line_length=30),
        "evidence_tab_indented": build(tabbed, loc(3, 3, 10, 14), context_lines=2),
        "evidence_wide_gutter": build(wide, loc(12_345), context_lines=2),
    }


@pytest.mark.parametrize("name", sorted(golden_cases()))
def test_golden(name: str) -> None:
    assert_matches_golden(golden_cases()[name].render_text(), GOLDEN / f"{name}.txt")


def test_wide_gutter_applies_to_every_line() -> None:
    lines = golden_cases()["evidence_wide_gutter"].render_text().splitlines()
    assert lines[0].startswith(" 12343 | ")
    assert lines[2].startswith(">12345 | ")
    assert lines[3].startswith("       | ^")


def test_tab_is_repeated_in_caret_line() -> None:
    text = golden_cases()["evidence_tab_indented"].render_text()
    assert "      | \t\t       ^^^^\n" in text


def test_no_carets_keeps_markers() -> None:
    text = worked_example().render_text(show_carets=False, marker="*")
    assert "^" not in text
    assert "*  88 | " in text
    assert len(text.splitlines()) == 4


def test_two_highlights_share_one_caret_line() -> None:
    text = manual(["a = b + c"], 5, [(5, 1, 2), (5, 9, 10)]).render_text()
    assert text == ">   5 | a = b + c\n      | ^       ^\n"


def test_clipped_and_truncated() -> None:
    evidence = build(fixture_200(), loc(80, 120), context_lines=0, max_lines=3)
    assert evidence.render_text().endswith("\n      | ...\n")
    truncated = build("x = '" + "y" * 50 + "'\n", loc(1), max_line_length=10)
    assert truncated.render_text().splitlines()[0] == ">   1 | x = 'yyyyy ..."


def test_highlight_on_trailing_blanks_has_no_caret_line() -> None:
    text = manual(["ab   "], 1, [(1, 3, 6)]).render_text()
    assert text == ">   1 | ab\n"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("x = '\x1b[31m'", "x = '\ufffd[31m'"),
        ("a\rb", "a\ufffdb"),
        ("a\x00b\x7fc\x85d", "a\ufffdb\ufffdc\ufffdd"),
        ("ok \u202e reversed", "ok \ufffd reversed"),
    ],
)
def test_control_characters_are_neutralised(source: str, expected: str) -> None:
    evidence = manual([source], 1, [])
    assert evidence.render_text() == f"    1 | {expected}\n"
    assert evidence.lines[0].text.expose() == source


@pytest.mark.parametrize("marker", ["ab", " ", "", "\t", "\x1b"])
def test_bad_marker(marker: str) -> None:
    with pytest.raises(ValueError, match="marker"):
        worked_example().render_text(marker=marker)


def test_highlight_beyond_line_is_rejected_by_the_model() -> None:
    with pytest.raises(ValidationError, match="beyond the end of its line"):
        manual(["abc"], 1, [(1, 2, 6)])


@given(cases(), st.integers(0, 5), st.integers(6, 40), st.integers(1, 80), st.booleans())
def test_render_properties(
    case: tuple[list[str], Location], context: int, max_lines: int, max_len: int, carets: bool
) -> None:
    lines, location = case
    source = "\n".join(lines) + "\n"
    evidence = build(
        source, location, context_lines=context, max_lines=max_lines, max_line_length=max_len
    )
    text = evidence.render_text(show_carets=carets)
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    rendered = text[:-1].split("\n")
    assert all(line == line.rstrip() for line in rendered)
    caret_lines = [
        i for i, line in enumerate(rendered) if line.startswith("      |") and "^" in line
    ]
    body = [line for i, line in enumerate(rendered) if i not in caret_lines]
    assert len(body) == len(evidence.lines) + (1 if evidence.clipped else 0)
    for index in caret_lines:
        assert len(rendered[index]) <= len(rendered[index - 1])
    if not carets:
        assert not caret_lines
