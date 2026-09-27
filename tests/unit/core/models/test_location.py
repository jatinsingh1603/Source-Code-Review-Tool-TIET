import json

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import DataClassification
from codekavach.core.models.location import CodeRegion, Location


def region(a: int, b: int, c: int | None = None, d: int | None = None) -> CodeRegion:
    return CodeRegion(start_line=a, end_line=b, start_col=c, end_col=d)


def test_path_is_normalised_in_json() -> None:
    loc = Location(path="src\\a.py", start_line=3, end_line=3)
    assert json.loads(loc.model_dump_json())["path"] == "src/a.py"


@pytest.mark.parametrize(
    "span",
    [
        {"start_line": 0, "end_line": 1},
        {"start_line": 3, "end_line": 2},
        {"start_line": 1, "end_line": 1, "start_col": 1},
        {"start_line": 1, "end_line": 1, "end_col": 3},
        {"start_line": 1, "end_line": 1, "start_col": 5, "end_col": 4},
        {"start_line": 1, "end_line": 1, "start_col": 0, "end_col": 4},
        {"start_line": 1, "end_line": 2, "start_col": 3, "end_col": 0},
    ],
)
def test_invalid_spans_rejected(span: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        CodeRegion(**span)
    with pytest.raises(ValidationError):
        Location.model_validate({"path": "a.py", **span})


def test_valid_spans() -> None:
    assert region(1, 1, 3, 3).line_count == 1  # zero width
    assert region(1, 3, 9, 2).line_count == 3  # multi-line end column may be smaller


def test_from_zero_based() -> None:
    dumped = Location.from_zero_based("a.py", 0, 0, 0, 3).model_dump()
    assert dumped["start_line"] == 1
    assert dumped["end_line"] == 1
    assert dumped["start_col"] == 1
    assert dumped["end_col"] == 4


def test_display_forms() -> None:
    assert (
        Location(path="src/app/db.py", start_line=42, end_line=42).display() == "src/app/db.py:42"
    )
    assert (
        Location(path="src/app/db.py", start_line=42, end_line=45).display()
        == "src/app/db.py:42-45"
    )
    assert (
        Location(path="src/app/db.py", start_line=42, end_line=42, start_col=7, end_col=9).display()
        == "src/app/db.py:42:7"
    )


def test_hashable_and_dict_keys() -> None:
    a = Location(path="a.py", start_line=1, end_line=2)
    b = Location(path="a.py", start_line=1, end_line=2)
    assert {a: 1}[b] == 1
    assert {region(1, 2): "x"}[region(1, 2)] == "x"


def test_classification() -> None:
    assert Location.DATA_CLASSIFICATION is DataClassification.RAW
    assert CodeRegion.DATA_CLASSIFICATION is DataClassification.METADATA


def test_json_keys_and_round_trip() -> None:
    loc = Location(path="a/b.py", start_line=1, end_line=1, start_col=2, end_col=5, symbol="A.f")
    data = json.loads(loc.model_dump_json())
    assert list(data) == ["path", "start_line", "end_line", "start_col", "end_col", "symbol"]
    assert Location.model_validate_json(loc.model_dump_json()) == loc
    assert "region" not in data


@pytest.mark.parametrize("symbol", ["", "   ", "a\x00b", "x" * 513])
def test_invalid_symbol(symbol: str) -> None:
    with pytest.raises(ValidationError):
        Location(path="a.py", start_line=1, end_line=1, symbol=symbol)


def test_symbol_is_stripped() -> None:
    assert Location(path="a.py", start_line=1, end_line=1, symbol=" A.f ").symbol == "A.f"


def test_region_round_trip() -> None:
    loc = Location(path="a.py", start_line=3, end_line=4, symbol="f")
    assert Location.from_region("a.py", loc.region, symbol="f") == loc
    assert loc.shift_lines(2).start_line == 5
    assert loc.shift_lines(2).path == "a.py"
    assert loc.sort_key() == ("a.py", 3, 0, 4, 0)


# region operations


def test_contains_and_overlaps_lines() -> None:
    outer = region(10, 20)
    assert outer.contains(region(12, 15))
    assert not outer.contains(region(15, 25))
    assert outer.overlaps(region(20, 30))  # adjacent on a shared line
    assert not outer.overlaps(region(21, 30))  # disjoint
    assert outer.contains_line(10)
    assert not outer.contains_line(21)


def test_contains_and_overlaps_columns_on_same_line() -> None:
    a = region(5, 5, 1, 4)
    assert a.contains(region(5, 5, 2, 3))
    assert not a.contains(region(5, 5, 2, 6))
    assert not a.overlaps(region(5, 5, 4, 6))  # end is exclusive
    assert a.overlaps(region(5, 5, 3, 6))
    assert a.overlaps(region(5, 5, 2, 2))  # zero width inside
    assert a.overlaps(region(5, 5))  # columns ignored when one side has none


def test_merge() -> None:
    assert region(1, 3).merge(region(5, 6)) == region(1, 6)
    assert region(2, 2, 3, 5).merge(region(2, 2, 1, 4)) == region(2, 2, 1, 5)
    assert region(2, 2, 3, 5).merge(region(3, 3, 1, 4)) == region(2, 3)


def test_shift() -> None:
    assert region(3, 4, 1, 2).shift(-2) == region(1, 2, 1, 2)
    with pytest.raises(ValueError, match="before line 1"):
        region(3, 4).shift(-3)


@st.composite
def regions(draw: st.DrawFn) -> CodeRegion:
    start = draw(st.integers(1, 30))
    end = draw(st.integers(start, start + 3))
    if draw(st.booleans()):
        c1 = draw(st.integers(1, 10))
        c2 = draw(st.integers(c1 if start == end else 1, 12))
        return region(start, end, c1, c2)
    return region(start, end)


@given(regions(), regions())
def test_overlap_is_symmetric(a: CodeRegion, b: CodeRegion) -> None:
    assert a.overlaps(b) == b.overlaps(a)


@given(regions(), regions())
def test_merge_contains_both(a: CodeRegion, b: CodeRegion) -> None:
    merged = a.merge(b)
    assert merged.contains(a)
    assert merged.contains(b)


@given(regions(), st.integers(-40, 40))
def test_shift_is_reversible(r: CodeRegion, delta: int) -> None:
    if r.start_line + delta < 1:
        return
    assert r.shift(delta).shift(-delta) == r
