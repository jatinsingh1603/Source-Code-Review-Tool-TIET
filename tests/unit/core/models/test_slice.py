import logging
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import (
    DataClassification,
    Language,
    SliceStrategy,
)
from codekavach.core.models.enums import SegmentRole, StubReason
from codekavach.core.models.ids import new_candidate_id, new_slice_id
from codekavach.core.models.location import CodeRegion
from codekavach.core.models.slice import CodeSlice, SliceSegment, Stub
from codekavach.core.models.text import RawCode

CANARY = "CANARY_9f3a"
LINE_SEPARATOR = chr(0x2028)


def seg(
    path: str,
    start: int,
    end: int,
    role: SegmentRole = SegmentRole.CONTEXT,
    text: str | None = None,
) -> SliceSegment:
    body = text if text is not None else "".join(f"line {n}\n" for n in range(start, end + 1))
    return SliceSegment(
        path=path, region=CodeRegion(start_line=start, end_line=end), text=RawCode(body), role=role
    )


def make(segments: tuple[SliceSegment, ...], **overrides: Any) -> CodeSlice:
    fields: dict[str, Any] = {
        "id": new_slice_id(),
        "candidate_id": new_candidate_id(),
        "language": Language.PYTHON,
        "strategy": SliceStrategy.ENCLOSING_FUNCTION,
        "segments": segments,
        "token_estimate": 412,
    }
    fields.update(overrides)
    return CodeSlice.model_validate(fields)


def example() -> CodeSlice:
    return make(
        (seg("src/bank/accounts.py", 80, 91, SegmentRole.PRIMARY),),
        stubs=(
            Stub(
                symbol="AuditLog.write",
                signature=RawCode("def write(self, event): ..."),
                reason=StubReason.OUT_OF_SLICE_CALLEE,
            ),
        ),
    )


def test_example_round_trips() -> None:
    code_slice = example()
    assert CodeSlice.model_validate_json(code_slice.model_dump_json()) == code_slice
    assert code_slice.schema_version == 1


def test_classification() -> None:
    for model in (SliceSegment, Stub, CodeSlice):
        assert model.DATA_CLASSIFICATION is DataClassification.RAW


def test_no_segments_rejected() -> None:
    with pytest.raises(ValidationError):
        make(())


def test_line_count_mismatch_rejected() -> None:
    with pytest.raises(ValidationError, match="number of lines"):
        seg("a.py", 1, 3, text="one\ntwo\n")


def test_region_with_columns_rejected() -> None:
    with pytest.raises(ValidationError, match="whole lines"):
        SliceSegment(
            path="a.py",
            region=CodeRegion(start_line=1, end_line=1, start_col=1, end_col=3),
            text=RawCode("ab"),
        )


def test_overlapping_segments_rejected() -> None:
    with pytest.raises(ValidationError, match="overlap"):
        make((seg("a.py", 1, 5, SegmentRole.PRIMARY), seg("a.py", 5, 8)))


def test_descending_segments_rejected() -> None:
    with pytest.raises(ValidationError, match="ascending"):
        make((seg("a.py", 10, 12, SegmentRole.PRIMARY), seg("a.py", 1, 3)))


def test_interleaved_paths_allowed() -> None:
    make((seg("a.py", 10, 12, SegmentRole.PRIMARY), seg("b.py", 1, 2), seg("a.py", 20, 21)))


@pytest.mark.parametrize("count", [0, 2])
def test_primary_count(count: int) -> None:
    roles = [SegmentRole.PRIMARY] * count + [SegmentRole.CONTEXT] * (2 - count)
    with pytest.raises(ValidationError, match="exactly one primary"):
        make((seg("a.py", 1, 2, roles[0]), seg("a.py", 5, 6, roles[1])))


def test_negative_token_estimate_rejected() -> None:
    with pytest.raises(ValidationError):
        make((seg("a.py", 1, 1, SegmentRole.PRIMARY),), token_estimate=-1)


def test_stub_symbol_validated() -> None:
    with pytest.raises(ValidationError):
        Stub(symbol="  ", signature=RawCode("def f(): ..."), reason=StubReason.TOKEN_BUDGET)
    with pytest.raises(ValidationError):
        Stub(symbol="f", signature=RawCode("x"), reason=StubReason.TOKEN_BUDGET, line=0)


def test_helpers_on_multi_file_slice() -> None:
    code_slice = make(
        (
            seg("app/views.py", 10, 12, SegmentRole.PRIMARY),
            seg("app/db.py", 40, 41, SegmentRole.TAINT_STEP),
            seg("app/views.py", 30, 30),
        )
    )
    assert code_slice.files == ("app/views.py", "app/db.py")
    assert code_slice.total_lines == 6
    assert code_slice.segment_for("app/db.py", 41) == 1
    assert code_slice.segment_for("app/views.py", 30) == 2
    assert code_slice.segment_for("app/views.py", 20) is None


def test_iter_numbered_lines() -> None:
    code_slice = make((seg("a.py", 10, 12, SegmentRole.PRIMARY), seg("a.py", 40, 41)))
    numbered = list(code_slice.iter_numbered_lines())
    assert [(i, n) for i, n, _ in numbered] == [(0, 10), (0, 11), (0, 12), (1, 40), (1, 41)]
    assert numbered[0][2] == "line 10"


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        ("a\nb\n", 2),
        ("a\r\nb\r\n", 2),
        ("\n", 1),
        (f"a\x0cb{LINE_SEPARATOR}c\nd", 2),
    ],
)
def test_line_model(text: str, lines: int) -> None:
    segment = seg("a.py", 1, lines, text=text)
    assert segment.region.line_count == lines


def test_canary_never_in_repr_str_or_logs(caplog: pytest.LogCaptureFixture) -> None:
    code_slice = make((seg("a.py", 1, 1, SegmentRole.PRIMARY, text=f"key = '{CANARY}'\n"),))
    assert CANARY not in repr(code_slice)
    assert CANARY not in str(code_slice)
    with caplog.at_level(logging.INFO, logger="test_slice"):
        logging.getLogger("test_slice").info("slice %s %r", code_slice, code_slice)
    assert CANARY not in caplog.text


@st.composite
def slices(draw: st.DrawFn) -> CodeSlice:
    paths = draw(st.lists(st.sampled_from(["a.py", "b/c.py", "d.js"]), min_size=1, max_size=6))
    next_line: dict[str, int] = {}
    segments = []
    for index, path in enumerate(paths):
        start = next_line.get(path, 1) + draw(st.integers(0, 5))
        end = start + draw(st.integers(0, 4))
        next_line[path] = end + 1
        role = SegmentRole.PRIMARY if index == 0 else SegmentRole.CONTEXT
        segments.append(seg(path, start, end, role))
    return make(tuple(segments), token_estimate=draw(st.integers(0, 10_000)))


@given(slices())
def test_random_slices_validate_and_round_trip(code_slice: CodeSlice) -> None:
    assert CodeSlice.model_validate_json(code_slice.model_dump_json()) == code_slice
