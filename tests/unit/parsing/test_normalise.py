"""Hidden-character detection and sentinel substitution (E07-01)."""

import tree_sitter as ts
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import Language
from codekavach.parsing.loader import load_language
from codekavach.parsing.normalise import (
    _BIDI_CONTROL,
    _BIDI_ISOLATE,
    _UNICODE_TAG,
    _ZERO_WIDTH,
    HiddenKind,
    normalise_source,
)

# A character from each class the module documents. Written as 8-digit \U escapes, never as a
# literal character, so no control character sits as a raw byte in this source file.
BIDI_CONTROL_CHAR = "\U0000202e"  # RIGHT-TO-LEFT OVERRIDE
BIDI_ISOLATE_CHAR = "\U00002066"  # LEFT-TO-RIGHT ISOLATE
ZERO_WIDTH_CHAR = "\U0000200b"  # ZERO WIDTH SPACE
UNICODE_TAG_CHAR = "\U000e0041"  # TAG LATIN CAPITAL LETTER A
BOM_CHAR = "\U0000feff"
HIDDEN_RANGES = (_BIDI_CONTROL, _BIDI_ISOLATE, _ZERO_WIDTH, _UNICODE_TAG)


def _node_types(source: str) -> list[str]:
    tree = ts.Parser(load_language(Language.PYTHON)).parse(source.encode("utf-8"))
    types: list[str] = []

    def walk(node: ts.Node) -> None:
        types.append(node.type)
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return types


def test_identity_for_a_file_with_no_hidden_character() -> None:
    text = "x = 1\ny = 2\n"
    normalised, report = normalise_source(text, "a.py")
    assert normalised == text
    assert normalised is text  # identity, not merely equal
    assert not report
    assert report.count == 0


def test_bidi_control_character_is_replaced_and_reported() -> None:
    text = f"x = 'a{BIDI_CONTROL_CHAR}b'\n"
    normalised, report = normalise_source(text, "a.py")
    assert len(normalised) == len(text)
    assert BIDI_CONTROL_CHAR not in normalised
    assert report.count == 1
    assert report.occurrences[0].kind is HiddenKind.BIDI_CONTROL


def test_bidi_isolate_character_is_replaced_and_reported() -> None:
    text = f"x = 'a{BIDI_ISOLATE_CHAR}b'\n"
    normalised, report = normalise_source(text, "a.py")
    assert len(normalised) == len(text)
    assert report.count == 1
    assert report.occurrences[0].kind is HiddenKind.BIDI_CONTROL


def test_zero_width_character_is_replaced_and_reported() -> None:
    text = f"x = 'a{ZERO_WIDTH_CHAR}b'\n"
    normalised, report = normalise_source(text, "a.py")
    assert len(normalised) == len(text)
    assert ZERO_WIDTH_CHAR not in normalised
    assert report.count == 1
    assert report.occurrences[0].kind is HiddenKind.ZERO_WIDTH


def test_unicode_tag_character_is_replaced_and_reported() -> None:
    text = f"x = 'a{UNICODE_TAG_CHAR}b'\n"
    normalised, report = normalise_source(text, "a.py")
    assert len(normalised) == len(text)
    assert UNICODE_TAG_CHAR not in normalised
    assert report.count == 1
    assert report.occurrences[0].kind is HiddenKind.UNICODE_TAG


def test_bom_at_the_very_start_is_left_alone() -> None:
    text = f"{BOM_CHAR}x = 1\n"
    normalised, report = normalise_source(text, "a.py")
    assert normalised == text
    assert not report


def test_bom_away_from_the_start_is_treated_as_zero_width() -> None:
    text = f"x = 1{BOM_CHAR}\n"
    normalised, report = normalise_source(text, "a.py")
    assert len(normalised) == len(text)
    assert report.count == 1
    assert report.occurrences[0].kind is HiddenKind.ZERO_WIDTH


def test_occurrence_location_points_at_the_hidden_character() -> None:
    text = f"line1\nx = 'a{ZERO_WIDTH_CHAR}b'\n"
    _, report = normalise_source(text, "a.py")
    (occurrence,) = report.occurrences
    assert occurrence.location.path == "a.py"
    assert occurrence.location.start_line == 2
    # line 2 is "x = 'a<hidden>b'"; 6 characters (x, space, =, space, ', a) precede it, column 7.
    assert occurrence.location.start_col == 7


def test_three_hidden_characters_reported_in_source_order_and_tree_matches_stripped() -> None:
    """Acceptance criterion: U+202E, U+200B and U+E0041 inside one string literal.

    The normalised text is the same length, reports the three occurrences, and parses to the
    same node-type sequence as the file with the hidden characters simply absent: a hidden
    character hidden inside a string literal never changes the token boundaries around it,
    whether it is there, substituted, or not there at all.
    """
    hidden = f"a{BIDI_CONTROL_CHAR}b{ZERO_WIDTH_CHAR}c{UNICODE_TAG_CHAR}d"
    stripped = "abcd"
    text = f"x = '{hidden}'\n"
    stripped_text = f"x = '{stripped}'\n"

    normalised, report = normalise_source(text, "a.py")
    assert len(normalised) == len(text)
    assert [item.kind for item in report.occurrences] == [
        HiddenKind.BIDI_CONTROL,
        HiddenKind.ZERO_WIDTH,
        HiddenKind.UNICODE_TAG,
    ]
    assert _node_types(normalised) == _node_types(stripped_text)


@given(
    text=st.text(
        # Real source text is always UTF-8 decoded from disk, so it never contains a lone
        # surrogate; codec="utf-8" keeps the strategy to characters an actual file can hold.
        alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x10FFFF, codec="utf-8")
    )
)
def test_normalise_source_preserves_length_and_removes_every_hidden_character(text: str) -> None:
    """Property: normalise_source preserves len(text) and leaves no hidden character."""
    normalised, _ = normalise_source(text, "a.py")
    assert len(normalised) == len(text)
    for char in normalised:
        point = ord(char)
        assert not any(point in r for r in HIDDEN_RANGES)
