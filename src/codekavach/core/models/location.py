"""Code spans and locations with one coordinate convention for the whole project.

Owning epic: E02.

Coordinates (normative):

- Lines are 1-based and inclusive; ``start_line <= end_line``.
- Columns are 1-based and count Unicode code points (a Python ``str`` index plus one).
  ``end_col`` is exclusive, as in SARIF 2.1.0: the first three characters of a line are
  ``start_col=1, end_col=4``.
- ``start_col`` and ``end_col`` are both ``None`` (whole lines) or both set; on a single line
  ``end_col >= start_col`` (equal is a zero-width insertion point).

``Location.from_zero_based`` converts tree-sitter style points (0-based rows and columns,
exclusive end) by adding one to each. Converting tree-sitter *byte* columns into code-point
columns needs the line text and is done by the parsing layer (E07), not here.
"""

from typing import ClassVar, Self

from pydantic import field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.paths import RepoPath

MAX_SYMBOL_LENGTH = 512


def _validate_span(
    start_line: int, end_line: int, start_col: int | None, end_col: int | None
) -> None:
    if start_line < 1:
        raise ValueError("start_line must be at least 1")
    if end_line < start_line:
        raise ValueError("end_line must not be before start_line")
    if (start_col is None) != (end_col is None):
        raise ValueError("start_col and end_col must both be set or both be None")
    if start_col is not None and end_col is not None:
        if start_col < 1 or end_col < 1:
            raise ValueError("columns are 1-based")
        if start_line == end_line and end_col < start_col:
            raise ValueError("end_col must not be before start_col on a single line")


class CodeRegion(KavachModel):
    """A span of lines, optionally with columns, without a path."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    start_line: int
    end_line: int
    start_col: int | None = None
    end_col: int | None = None

    @model_validator(mode="after")
    def _check_span(self) -> Self:
        _validate_span(self.start_line, self.end_line, self.start_col, self.end_col)
        return self

    @property
    def line_count(self) -> int:
        """Number of lines covered."""
        return self.end_line - self.start_line + 1

    def _columns(self) -> tuple[int, int] | None:
        if self.start_line != self.end_line or self.start_col is None or self.end_col is None:
            return None
        return self.start_col, self.end_col

    def _shared_line_columns(
        self, other: "CodeRegion"
    ) -> tuple[tuple[int, int], tuple[int, int]] | None:
        """Both column ranges when both regions sit on the same single line with columns."""
        mine, theirs = self._columns(), other._columns()
        if mine is None or theirs is None or self.start_line != other.start_line:
            return None
        return mine, theirs

    def contains_line(self, line: int) -> bool:
        """True when ``line`` lies inside the region."""
        return self.start_line <= line <= self.end_line

    def contains(self, other: "CodeRegion") -> bool:
        """True when ``other`` lies inside this region.

        Columns are compared only when both regions are on the same single line and both
        have columns.
        """
        columns = self._shared_line_columns(other)
        if columns is not None:
            (start, end), (other_start, other_end) = columns
            return start <= other_start and other_end <= end
        return self.start_line <= other.start_line and other.end_line <= self.end_line

    def overlaps(self, other: "CodeRegion") -> bool:
        """True when the regions share at least one line (or column range, see ``contains``)."""
        columns = self._shared_line_columns(other)
        if columns is not None:
            (start, end), (other_start, other_end) = columns
            if start == end:
                return other_start <= start <= other_end
            if other_start == other_end:
                return start <= other_start <= end
            return max(start, other_start) < min(end, other_end)
        return self.start_line <= other.end_line and other.start_line <= self.end_line

    def shift(self, delta: int) -> Self:
        """Return the region moved by ``delta`` lines.

        Raises:
            ValueError: a line would fall below 1.
        """
        if self.start_line + delta < 1:
            raise ValueError("shift would move the region before line 1")
        return self.evolve(start_line=self.start_line + delta, end_line=self.end_line + delta)

    def merge(self, other: "CodeRegion") -> "CodeRegion":
        """Return the smallest region covering both; columns survive only on a single line."""
        start = min(self.start_line, other.start_line)
        end = max(self.end_line, other.end_line)
        columns = self._shared_line_columns(other)
        if start == end and columns is not None:
            (col_start, col_end), (other_start, other_end) = columns
            return CodeRegion(
                start_line=start,
                end_line=end,
                start_col=min(col_start, other_start),
                end_col=max(col_end, other_end),
            )
        return CodeRegion(start_line=start, end_line=end)

    def sort_key(self) -> tuple[int, int, int, int]:
        """Key for a stable ordering by position."""
        return (self.start_line, self.start_col or 0, self.end_line, self.end_col or 0)


class Location(KavachModel):
    """A place in the client's code. Client data: never part of anything sent to an LLM."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    path: RepoPath
    start_line: int
    end_line: int
    start_col: int | None = None
    end_col: int | None = None
    symbol: str | None = None

    @field_validator("symbol")
    @classmethod
    def _check_symbol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not 1 <= len(stripped) <= MAX_SYMBOL_LENGTH:
            raise ValueError("symbol must be 1 to 512 characters after stripping")
        if any(ord(char) < 32 or 127 <= ord(char) < 160 for char in stripped):
            raise ValueError("symbol must not contain control characters")
        return stripped

    @model_validator(mode="after")
    def _check_span(self) -> Self:
        _validate_span(self.start_line, self.end_line, self.start_col, self.end_col)
        return self

    @property
    def region(self) -> CodeRegion:
        """The span of this location without its path."""
        return CodeRegion(
            start_line=self.start_line,
            end_line=self.end_line,
            start_col=self.start_col,
            end_col=self.end_col,
        )

    @classmethod
    def from_region(cls, path: str, region: CodeRegion, symbol: str | None = None) -> Self:
        """Build a location from a path and a region."""
        return cls(
            path=path,
            start_line=region.start_line,
            end_line=region.end_line,
            start_col=region.start_col,
            end_col=region.end_col,
            symbol=symbol,
        )

    @classmethod
    def from_zero_based(  # noqa: PLR0917 - positional signature mirrors tree-sitter points
        cls,
        path: str,
        start_row: int,
        start_col: int,
        end_row: int,
        end_col: int,
        symbol: str | None = None,
    ) -> Self:
        """Build a location from 0-based rows and columns with an exclusive end column."""
        return cls(
            path=path,
            start_line=start_row + 1,
            end_line=end_row + 1,
            start_col=start_col + 1,
            end_col=end_col + 1,
            symbol=symbol,
        )

    def shift_lines(self, delta: int) -> Self:
        """Return the location moved by ``delta`` lines."""
        region = self.region.shift(delta)
        return self.evolve(start_line=region.start_line, end_line=region.end_line)

    def display(self) -> str:
        """Short human form: ``path:42``, ``path:42-45`` or ``path:42:7``."""
        if self.start_line != self.end_line:
            return f"{self.path}:{self.start_line}-{self.end_line}"
        if self.start_col is not None:
            return f"{self.path}:{self.start_line}:{self.start_col}"
        return f"{self.path}:{self.start_line}"

    def sort_key(self) -> tuple[str, int, int, int, int]:
        """Key for a stable ordering by path, then position."""
        return (self.path, *self.region.sort_key())
