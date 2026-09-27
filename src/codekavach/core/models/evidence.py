"""Evidence: text code snippets with line numbers and highlight ranges (requirement R9).

Owning epic: E02.

Evidence is raw client code, produced and consumed only inside the client environment. It must
never reach codekavach.llm (invariant I2). Line text is held as ``RawCode`` so it cannot leak
through logging. Producers of secret findings may mask the secret before building the evidence
and set ``masked``; renderers then add a note.

Columns are 1-based code points with an exclusive end, as in ``Location``. A tab counts as one
code point; renderers decide on tab expansion.
"""

from typing import ClassVar, Self

from pydantic import Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import EvidenceRole, Language
from codekavach.core.models.location import Location
from codekavach.core.models.text import RawCode, split_lines


class SnippetLine(KavachModel):
    """One file line of a snippet, without its line terminator."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    number: int = Field(ge=1)
    text: RawCode
    truncated: bool = False

    @field_validator("text")
    @classmethod
    def _single_line(cls, value: RawCode) -> RawCode:
        if "\n" in value.expose():
            raise ValueError("a snippet line must not contain a line break")
        return value


class HighlightRange(KavachModel):
    """A highlighted column range on one snippet line."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    line: int = Field(ge=1)
    start_col: int = Field(ge=1)
    end_col: int

    @model_validator(mode="after")
    def _check_columns(self) -> Self:
        if self.end_col <= self.start_col:
            raise ValueError("end_col must be greater than start_col")
        return self


def _first_non_blank(text: str) -> int | None:
    for index, char in enumerate(text):
        if not char.isspace():
            return index + 1
    return None


def _line_ranges(location: Location, number: int, text: str) -> tuple[int, int] | None:
    """Unclipped highlight ``[start, end)`` for one region line, or None.

    Columns beyond the end of the line are clamped, because engines that count bytes or UTF-16
    units overshoot on non-ASCII lines.
    """
    first = _first_non_blank(text)
    if first is None:
        return None
    line_end = len(text) + 1
    start, end = first, line_end
    start_col, end_col = location.start_col, location.end_col
    if start_col is not None and end_col is not None:
        if location.start_line == location.end_line and end_col == start_col:
            return None
        if number == location.start_line:
            start = min(start_col, line_end)
        if number == location.end_line:
            end = min(end_col, line_end)
    return start, end


class Evidence(KavachModel):
    """A snippet of client code with context lines and highlights for one location."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    location: Location
    language: Language
    lines: tuple[SnippetLine, ...] = Field(min_length=1)
    highlights: tuple[HighlightRange, ...] = ()
    role: EvidenceRole = EvidenceRole.PRIMARY
    caption: str | None = Field(default=None, max_length=300)
    masked: bool = False
    clipped: bool = False

    @model_validator(mode="after")
    def _check_snippet(self) -> Self:
        numbers = [line.number for line in self.lines]
        if numbers != list(range(numbers[0], numbers[0] + len(numbers))):
            raise ValueError("snippet lines must be contiguous and ascending")
        first, last = numbers[0], numbers[-1]
        if not first <= self.location.start_line <= last:
            raise ValueError("the location's start line must be inside the snippet")
        if not self.clipped and self.location.end_line > last:
            raise ValueError("the location extends beyond an unclipped snippet")
        lengths = {line.number: len(line.text) for line in self.lines}
        previous: HighlightRange | None = None
        for highlight in self.highlights:
            if highlight.line not in lengths:
                raise ValueError("a highlight lies outside the snippet")
            if highlight.end_col > lengths[highlight.line] + 1:
                raise ValueError("a highlight extends beyond the end of its line")
            if previous is not None:
                if (highlight.line, highlight.start_col) < (previous.line, previous.start_col):
                    raise ValueError("highlights must be sorted by line and column")
                if highlight.line == previous.line and highlight.start_col < previous.end_col:
                    raise ValueError("highlights on one line must not overlap")
            previous = highlight
        return self

    @classmethod
    def from_source(
        cls,
        source: RawCode,
        location: Location,
        *,
        language: Language,
        context_lines: int = 3,
        max_lines: int = 40,
        max_line_length: int = 400,
        role: EvidenceRole = EvidenceRole.PRIMARY,
        caption: str | None = None,
    ) -> Self:
        """Cut a snippet with context lines and highlights out of ``source``.

        Raises:
            ValueError: the location ends beyond the source, or ``max_lines`` is not greater
                than ``context_lines``. Messages never contain source text.
        """
        if max_lines <= context_lines:
            raise ValueError("max_lines must be greater than context_lines")
        all_lines = split_lines(source.expose())
        total = len(all_lines)
        if location.end_line > total:
            raise ValueError(
                f"location ends at line {location.end_line} but the source has {total} lines"
            )
        first = max(1, location.start_line - context_lines)
        last = min(total, location.end_line + context_lines)
        clipped = False
        if last - first + 1 > max_lines:
            last = first + max_lines - 1
            clipped = True

        lines: list[SnippetLine] = []
        highlights: list[HighlightRange] = []
        for number in range(first, last + 1):
            full = all_lines[number - 1]
            truncated = len(full) > max_line_length
            text = full[:max_line_length] if truncated else full
            lines.append(SnippetLine(number=number, text=RawCode(text), truncated=truncated))
            if not location.start_line <= number <= location.end_line:
                continue
            span = _line_ranges(location, number, full)
            if span is None:
                continue
            start, end = span[0], min(span[1], len(text) + 1)
            if start < end:
                highlights.append(HighlightRange(line=number, start_col=start, end_col=end))
        return cls(
            location=location,
            language=language,
            lines=tuple(lines),
            highlights=tuple(highlights),
            role=role,
            caption=caption,
            clipped=clipped,
        )
