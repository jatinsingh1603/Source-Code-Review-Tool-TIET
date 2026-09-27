"""Code slices: the minimal raw code context for one candidate.

Owning epic: E02. A slice still contains raw client code, so ``SliceSegment``, ``Stub`` and
``CodeSlice`` sit on the trusted side of invariant I2: nothing under codekavach.llm may import
or accept them. Text is held as ``RawCode`` so it never appears in logs or exception text.
"""

from collections.abc import Iterator
from typing import ClassVar, Self

from pydantic import Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.enums import Language, SegmentRole, SliceStrategy, StubReason
from codekavach.core.models.ids import CandidateIdField, SliceIdField
from codekavach.core.models.location import CodeRegion, check_symbol
from codekavach.core.models.paths import RepoPath
from codekavach.core.models.text import RawCode, split_lines


class SliceSegment(KavachModel):
    """A contiguous range of whole lines of one file, with their text."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    path: RepoPath
    region: CodeRegion
    text: RawCode
    role: SegmentRole = SegmentRole.CONTEXT

    @model_validator(mode="after")
    def _check_geometry(self) -> Self:
        if self.region.start_col is not None:
            raise ValueError("a slice segment covers whole lines; its region has no columns")
        if self.text.line_count != self.region.line_count:
            raise ValueError("segment text and region have a different number of lines")
        return self


class Stub(KavachModel):
    """Signature of a callee whose body was left out of the slice."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    symbol: str
    signature: RawCode
    reason: StubReason
    path: RepoPath | None = None
    line: int | None = Field(default=None, ge=1)

    @field_validator("symbol")
    @classmethod
    def _check_symbol(cls, value: str) -> str:
        return check_symbol(value)


class CodeSlice(VersionedModel):
    """Minimal code context for one candidate, built by the slicer (E11)."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW
    SCHEMA_VERSION: ClassVar[int] = 1

    id: SliceIdField
    candidate_id: CandidateIdField
    language: Language
    strategy: SliceStrategy
    segments: tuple[SliceSegment, ...] = Field(min_length=1)
    stubs: tuple[Stub, ...] = ()
    token_estimate: int = Field(ge=0)
    truncated: bool = False

    @model_validator(mode="after")
    def _check_segments(self) -> Self:
        primaries = sum(1 for segment in self.segments if segment.role is SegmentRole.PRIMARY)
        if primaries != 1:
            raise ValueError("a slice needs exactly one primary segment")
        last_end: dict[str, int] = {}
        for segment in self.segments:
            previous = last_end.get(segment.path)
            if previous is not None and segment.region.start_line <= previous:
                raise ValueError(
                    "segments of one file must not overlap and must be in ascending line order"
                )
            last_end[segment.path] = segment.region.end_line
        return self

    @property
    def files(self) -> tuple[str, ...]:
        """Distinct paths in first-seen order."""
        return tuple(dict.fromkeys(segment.path for segment in self.segments))

    @property
    def total_lines(self) -> int:
        """Number of lines over all segments."""
        return sum(segment.region.line_count for segment in self.segments)

    def segment_for(self, path: str, line: int) -> int | None:
        """Index of the segment that contains ``line`` of ``path``, or None."""
        for index, segment in enumerate(self.segments):
            if segment.path == path and segment.region.contains_line(line):
                return index
        return None

    def iter_numbered_lines(self) -> Iterator[tuple[int, int, str]]:
        """Yield ``(segment_index, file_line, text)`` for every line of the slice.

        Warning: this yields raw client code as plain ``str``. Use it only in
        codekavach.privacy and codekavach.report.
        """
        for index, segment in enumerate(self.segments):
            for offset, text in enumerate(split_lines(segment.text.expose())):
                yield index, segment.region.start_line + offset, text
