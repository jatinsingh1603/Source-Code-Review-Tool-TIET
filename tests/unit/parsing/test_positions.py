"""``LineIndex``: byte offset to code-point ``Location`` conversion (E07-01)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.parsing.positions import LineIndex
from tests.support.parsing import reference_position

# One row per required case: a 2-byte, a 3-byte and a 4-byte (astral) character, a combining
# sequence, and a line that begins with a BOM. ``char`` sits between an ``x`` and a ``y`` on its
# own line; ``byte_offset`` is the offset of the first byte of ``char``.
CASES = [
    pytest.param("xéy\n", 1, (1, 2), id="2-byte-e-acute"),
    pytest.param("x€y\n", 1, (1, 2), id="3-byte-euro-sign"),
    pytest.param("x\U0001f600y\n", 1, (1, 2), id="4-byte-astral-emoji"),
    # "x", "e", COMBINING ACUTE ACCENT, "y": querying right after the combining mark (byte 4,
    # the start of "y") counts it as its own code point, giving column 4 (3 characters precede).
    pytest.param("xéy\n", 4, (1, 4), id="combining-sequence-e-plus-acute"),
    # The BOM is one code point (3 bytes); querying right after it (byte 3, the start of "x")
    # counts only the BOM as preceding, giving column 2.
    pytest.param("﻿xy\n", 3, (1, 2), id="bom-at-line-start"),
]


@pytest.mark.parametrize(("text", "byte_offset", "expected"), CASES)
def test_position_multibyte_table(text: str, byte_offset: int, expected: tuple[int, int]) -> None:
    index = LineIndex.build(text)
    assert index.position(byte_offset) == expected
    assert index.position(byte_offset) == reference_position(text, byte_offset)


def test_position_every_offset_of_a_multiline_multibyte_file() -> None:
    text = "x = 1\ny = 'é€\U0001f600'\n# énd\n"
    index = LineIndex.build(text)
    data = text.encode("utf-8")
    for offset in range(len(data) + 1):
        assert index.position(offset) == reference_position(text, offset)


def test_position_is_identity_for_empty_text() -> None:
    index = LineIndex.build("")
    assert index.position(0) == (1, 1)


def test_position_clamps_an_out_of_range_offset() -> None:
    index = LineIndex.build("abc\n")
    assert index.position(-5) == index.position(0)
    assert index.position(1000) == index.position(4)


def test_location_builds_a_span_with_a_path() -> None:
    index = LineIndex.build("x = 1\n")
    location = index.location("a/b.py", 0, 1)
    assert location.path == "a/b.py"
    assert (location.start_line, location.start_col) == (1, 1)
    assert (location.end_line, location.end_col) == (1, 2)


@given(
    text=st.text(min_size=0, max_size=200),
    fraction=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
)
def test_position_agrees_with_reference_for_random_text(text: str, fraction: float) -> None:
    """Property: for random UTF-8 text, LineIndex.position agrees with a slow reference."""
    index = LineIndex.build(text)
    total = len(text.encode("utf-8"))
    offset = int(fraction * total)
    assert index.position(offset) == reference_position(text, offset)
