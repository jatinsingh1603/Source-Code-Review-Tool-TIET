"""The rename plan and its application (E09-04).

A plan is checked before any text exists: sorted, non-overlapping, on character boundaries and
clear of placeholder tokens. Applying it takes the edits from the end, so every offset is the
original's.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import RawCode
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.apply import apply_plan
from codekavach.privacy.pseudonymise.plan import (
    EditReason,
    RenameEdit,
    RenamePlan,
    edits_around_placeholders,
    placeholder_byte_ranges,
)

TOKEN = "<SECRET:api_key:1>"


def edit(
    start: int, end: int, text: str = "Z", reason: EditReason = EditReason.IDENTIFIER
) -> RenameEdit:
    return RenameEdit(start, end, text, reason)


def plan_of(*edits: RenameEdit) -> RenamePlan:
    return RenamePlan(tuple(edits))


# --- validation -------------------------------------------------------------------------------


def test_build_sorts_the_three_kinds_of_edit_into_one_list() -> None:
    plan = RenamePlan.build(
        [edit(10, 12)],
        [edit(0, 3, reason=EditReason.LITERAL)],
        [edit(5, 7, reason=EditReason.COMMENT)],
    )
    assert [e.start_byte for e in plan.edits] == [0, 5, 10]


def test_a_valid_plan_passes_and_adjacent_edits_are_not_overlap() -> None:
    plan_of(edit(0, 3), edit(3, 5), edit(5, 5, "ins")).validate(b"abcdefgh")


def test_unsorted_edits_are_refused() -> None:
    with pytest.raises(PseudonymError, match="sorted"):
        plan_of(edit(4, 6), edit(0, 2)).validate(b"abcdefgh")


def test_overlapping_edits_are_refused_and_name_both_reasons() -> None:
    plan = plan_of(edit(0, 5, reason=EditReason.IDENTIFIER), edit(3, 8, reason=EditReason.LITERAL))
    with pytest.raises(PseudonymError) as caught:
        plan.validate(b"abcdefghij")
    assert "identifier" in str(caught.value)
    assert "literal" in str(caught.value)


def test_two_edits_of_the_same_range_are_refused() -> None:
    with pytest.raises(PseudonymError, match="overlap"):
        plan_of(edit(2, 4), edit(2, 4, reason=EditReason.COMMENT)).validate(b"abcdefgh")


def test_overlap_produces_no_text() -> None:
    plan = plan_of(edit(0, 5), edit(4, 6, reason=EditReason.NAME_STRING))
    with pytest.raises(PseudonymError):
        apply_plan(RawCode("abcdefgh"), plan)


def test_an_edit_beyond_the_source_is_refused() -> None:
    with pytest.raises(PseudonymError, match="beyond"):
        plan_of(edit(0, 99)).validate(b"abc")


def test_an_inverted_or_negative_range_is_refused_at_construction() -> None:
    with pytest.raises(PseudonymError):
        RenameEdit(5, 2, "x", EditReason.IDENTIFIER)
    with pytest.raises(PseudonymError):
        RenameEdit(-1, 2, "x", EditReason.IDENTIFIER)


@pytest.mark.parametrize(("start", "end"), [(0, 1), (1, 2), (1, 1)])
def test_an_edit_that_would_split_a_multibyte_character_is_refused(start: int, end: int) -> None:
    source = "é".encode()  # two bytes
    with pytest.raises(PseudonymError, match="multi-byte"):
        plan_of(edit(start, end)).validate(source)


def test_an_edit_over_whole_multibyte_characters_is_accepted() -> None:
    source = "aé日b".encode()
    plan_of(edit(1, 3), edit(3, 6)).validate(source)
    assert apply_plan(RawCode("aé日b"), plan_of(edit(1, 3, "e"), edit(3, 6, "j"))) == "aejb"


SOURCE = f"x = '{TOKEN}' + y".encode()
START = SOURCE.index(b"<")
END = START + len(TOKEN)


def test_placeholder_ranges_are_byte_ranges() -> None:
    assert placeholder_byte_ranges(SOURCE) == ((START, END),)
    wide = f"é {TOKEN}".encode()
    assert placeholder_byte_ranges(wide) == ((3, 3 + len(TOKEN)),)


@pytest.mark.parametrize(
    ("start", "end"),
    [
        (START, END),
        (START + 3, START + 5),
        (START - 1, START + 1),
        (END - 1, END + 1),
        (START, START + 1),
    ],
)
def test_an_edit_touching_a_placeholder_is_refused(start: int, end: int) -> None:
    with pytest.raises(PseudonymError, match="placeholder"):
        plan_of(edit(start, end)).validate(SOURCE)


def test_an_insertion_inside_a_placeholder_is_refused() -> None:
    with pytest.raises(PseudonymError, match="placeholder"):
        plan_of(edit(START + 4, START + 4, "ins")).validate(SOURCE)


@pytest.mark.parametrize(
    ("start", "end"), [(0, START), (END, len(SOURCE)), (START, START), (END, END), (0, START - 1)]
)
def test_edits_next_to_a_placeholder_are_accepted(start: int, end: int) -> None:
    plan_of(edit(start, end)).validate(SOURCE)


def test_a_plan_shows_a_count_and_never_text() -> None:
    plan = plan_of(edit(0, 3, "secret_replacement"))
    assert "secret_replacement" not in repr(plan)
    assert "1" in repr(plan)


# --- applying ---------------------------------------------------------------------------------


def test_an_empty_plan_returns_the_source() -> None:
    assert apply_plan(RawCode("keep me\n"), RenamePlan()) == "keep me\n"


def test_edits_at_the_start_and_the_end() -> None:
    plan = plan_of(edit(0, 1, "AA"), edit(4, 5, "ZZ"))
    assert apply_plan(RawCode("abcde"), plan) == "AAbcdZZ"


def test_adjacent_edits_and_an_insertion() -> None:
    plan = plan_of(edit(0, 2, "X"), edit(2, 4, "Y"), edit(4, 4, "-"))
    assert apply_plan(RawCode("abcdef"), plan) == "XY-ef"


def test_a_replacement_longer_or_shorter_than_its_range_keeps_the_rest_in_place() -> None:
    plan = plan_of(edit(1, 2, "LONGER"), edit(3, 6, ""))
    assert apply_plan(RawCode("abcdefg"), plan) == "aLONGERcg"


@given(
    text=st.text(alphabet="abcdéλ ", min_size=0, max_size=40),
    cuts=st.lists(st.integers(min_value=0, max_value=40), max_size=8),
)
def test_applying_matches_a_naive_splice(text: str, cuts: list[int]) -> None:
    points = sorted({min(cut, len(text)) for cut in cuts})
    pairs = list(zip(points[::2], points[1::2], strict=False))
    data = text.encode()
    byte_offset = [len(text[:i].encode()) for i in range(len(text) + 1)]
    edits = [edit(byte_offset[a], byte_offset[b], f"<{n}>") for n, (a, b) in enumerate(pairs)]
    expected = text
    for (a, b), made in reversed(list(zip(pairs, edits, strict=True))):
        expected = expected[:a] + made.replacement + expected[b:]
    plan = plan_of(*edits)
    plan.validate(data)
    assert apply_plan(RawCode(text), plan) == expected


# --- edits around placeholders ----------------------------------------------------------------


def test_edits_around_placeholders_skip_the_token_and_unchanged_pieces() -> None:
    original = f"abc {TOKEN} def"
    made = edits_around_placeholders(10, original, f"xyz {TOKEN} def", EditReason.LITERAL)
    assert [(e.start_byte, e.end_byte, e.replacement) for e in made] == [(10, 14, "xyz ")]
    RenamePlan.build([], made, [], source=(b"?" * 10) + original.encode())


def test_edits_around_placeholders_with_two_tokens_and_multibyte_text() -> None:
    original = f"é{TOKEN}ü{TOKEN}z"
    replacement = f"e{TOKEN}u{TOKEN}Z"
    made = edits_around_placeholders(0, original, replacement, EditReason.COMMENT)
    assert [e.replacement for e in made] == ["e", "u", "Z"]
    plan = RenamePlan.build([], [], made, source=original.encode())
    assert apply_plan(RawCode(original), plan) == replacement


def test_a_replacement_that_loses_a_placeholder_is_refused() -> None:
    with pytest.raises(PseudonymError, match="placeholder"):
        edits_around_placeholders(0, f"a {TOKEN}", "a xxxxx", EditReason.LITERAL)
    with pytest.raises(PseudonymError, match="placeholder"):
        edits_around_placeholders(0, "a b", f"a {TOKEN}", EditReason.LITERAL)


def test_no_placeholder_means_one_edit_or_none() -> None:
    assert edits_around_placeholders(3, "same", "same", EditReason.LITERAL) == []
    (only,) = edits_around_placeholders(3, "old", "new", EditReason.LITERAL)
    assert (only.start_byte, only.end_byte, only.replacement) == (3, 6, "new")
