r"""UTF-8 byte offset to code-point ``Location`` conversion (E07-01).

Owning epic: E07.

tree-sitter reports node spans as UTF-8 byte offsets; ``Location`` (E02-07) declares columns in
1-based Unicode code points, because that is what an editor shows and what a report reader
counts. Re-decoding ``text[:offset]`` for every node is quadratic in file size and dominates the
scan on a large, minified file, so this module builds two small arrays once per file and answers
every conversion with two binary searches.

``LineIndex.build`` splits the encoded text on ``b"\\n"`` only (the project line model in
``codekavach.core.models.text``, never the Unicode-aware ``str.splitlines``), so a ``\\r`` before
a ``\\n`` is ordinary text on the preceding line, exactly as ``split_lines`` treats it; this
module never rewrites line endings, only reads them. A query byte offset that falls strictly
inside a multi-byte character (never produced by tree-sitter itself, but reachable from a
hand-built offset) resolves to the column *before* that character, as if it had not been reached
yet; this is the one well-defined choice and the property test pins it.
"""

import bisect
from dataclasses import dataclass

from codekavach.core.models import CodeRegion, Location


@dataclass(frozen=True, slots=True)
class LineIndex:
    """Precomputed byte/code-point arithmetic for one source text.

    ``_line_start_bytes[i]`` is the byte offset of the first byte of line ``i`` (0-based).
    ``_char_boundaries[i]`` is the cumulative UTF-8 byte length of each code point of line ``i``,
    starting with 0; its last entry is the byte length of the line's content, excluding the
    terminator.
    """

    _line_start_bytes: tuple[int, ...]
    _char_boundaries: tuple[tuple[int, ...], ...]
    _total_bytes: int

    @classmethod
    def build(cls, text: str) -> "LineIndex":
        """Build the index once; linear in the length of ``text``.

        A line that is pure ASCII (one byte per code point, true for most source lines) skips
        the per-character loop entirely: its boundaries are just ``range(len(line) + 1)``. This
        keeps an ordinary file's build close to the cost of encoding it once; only a line with a
        multi-byte character pays for the exact per-character prefix sum.
        """
        lines = text.split("\n")
        line_start_bytes = [0]
        char_boundaries: list[tuple[int, ...]] = []
        last = len(lines) - 1
        for index, line in enumerate(lines):
            line_byte_length = len(line.encode("utf-8"))
            if len(line) == line_byte_length:
                char_boundaries.append(tuple(range(len(line) + 1)))
            else:
                boundaries = [0]
                total = 0
                for char in line:
                    total += len(char.encode("utf-8"))
                    boundaries.append(total)
                char_boundaries.append(tuple(boundaries))
            next_start = line_start_bytes[-1] + line_byte_length
            if index < last:
                next_start += 1  # the '\n' terminator, present after every line but the last
            line_start_bytes.append(next_start)
        total_bytes = line_start_bytes.pop()
        return cls(tuple(line_start_bytes), tuple(char_boundaries), total_bytes)

    def _locate(self, byte_offset: int) -> tuple[int, int]:
        """Return the 0-based line index and the 1-based code-point column."""
        offset = min(max(byte_offset, 0), self._total_bytes)
        line_index = bisect.bisect_right(self._line_start_bytes, offset) - 1
        offset_in_line = offset - self._line_start_bytes[line_index]
        column = bisect.bisect_right(self._char_boundaries[line_index], offset_in_line)
        return line_index, column

    def position(self, byte_offset: int) -> tuple[int, int]:
        """1-based ``(line, code_point_column)`` for one UTF-8 byte offset.

        A ``byte_offset`` outside ``[0, len(text.encode("utf-8"))]`` is clamped rather than
        raised: a caller passing a tree-sitter-derived offset never triggers this, and clamping
        keeps a malformed offset from aborting an otherwise-useful parse.
        """
        line_index, column = self._locate(byte_offset)
        return line_index + 1, column

    def location(
        self, path: str, start_byte: int, end_byte: int, symbol: str | None = None
    ) -> Location:
        """The ``Location`` spanning ``[start_byte, end_byte)`` of the indexed text."""
        start_line, start_col = self.position(start_byte)
        end_line, end_col = self.position(end_byte)
        return Location(
            path=path,
            start_line=start_line,
            end_line=end_line,
            start_col=start_col,
            end_col=end_col,
            symbol=symbol,
        )

    def region(self, start_byte: int, end_byte: int) -> CodeRegion:
        """The path-free ``CodeRegion`` spanning ``[start_byte, end_byte)`` of the indexed text."""
        start_line, start_col = self.position(start_byte)
        end_line, end_col = self.position(end_byte)
        return CodeRegion(
            start_line=start_line, end_line=end_line, start_col=start_col, end_col=end_col
        )
