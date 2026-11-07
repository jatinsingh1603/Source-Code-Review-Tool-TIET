"""The line structure of a payload, and the line map that follows from it (E09-05).

Owning epic: E09.

A payload is laid out in a fixed order, a pure function of the slice (invariant I5): a header
comment that names only the level, then each file in path order as a label comment followed by its
segments (an elision marker where lines are left out between two of them), then a blank line and
the stubs. Every line has one of the kinds of :class:`LineKind`, and only ``SEGMENT`` lines come
from a file:

* a segment line maps to its file line;
* a header, a label, an elision marker, a blank line or a stub line maps to nothing and is not
  covered by any entry;
* a comment that the pseudonymiser blanks keeps its line, so the map is unchanged by blanking.

The text that the redactor works on is ``layout_of(slice_, level).text``. The pseudonymiser checks
that the redaction has kept this line structure; it fails closed if not.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from codekavach.core.models import CodeSlice, Language, LineMapEntry, PrivacyLevel
from codekavach.core.models.text import split_lines
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.slicing.assemble import numbered_labels
from codekavach.privacy.slicing.elide import comment_prefix, elision_marker

_FRAMED_LEVEL: Final = PrivacyLevel.L3


class LineKind(StrEnum):
    """What a payload line is."""

    HEADER = "header"
    LABEL = "label"
    SEGMENT = "segment"
    ELISION = "elision"
    SEPARATOR = "separator"
    STUB = "stub"


@dataclass(frozen=True, slots=True, repr=False)
class LayoutLine:
    """One line of a payload: its kind, its text in the layout and where it comes from."""

    kind: LineKind
    text: str
    path: str | None = None
    segment_index: int | None = None
    file_line: int | None = None

    def __repr__(self) -> str:
        return f"LayoutLine({self.kind.value})"


@dataclass(frozen=True, slots=True, repr=False)
class PayloadLayout:
    """The lines of a payload before redaction and pseudonymisation."""

    language: Language
    lines: tuple[LayoutLine, ...]

    def __repr__(self) -> str:
        return f"PayloadLayout({len(self.lines)} lines)"

    @property
    def text(self) -> str:
        """The lines, each ended by a newline, so that a final blank line is kept."""
        return "\n".join(line.text for line in self.lines) + "\n"


def header_text(language: Language, level: PrivacyLevel) -> str:
    """The header comment: the level and nothing else."""
    return f"{comment_prefix(language)} codekavach payload {level.value}"


def layout_of(slice_: CodeSlice, level: PrivacyLevel, *, framed: bool = True) -> PayloadLayout:
    """The layout of ``slice_`` at ``level``.

    ``framed=False`` leaves out the header and the file labels, which is the bare form of segments,
    elision markers and stubs.
    """
    language = slice_.language
    prefix = comment_prefix(language)
    marker = elision_marker(language)
    labels = numbered_labels(segment.path for segment in slice_.segments)
    lines: list[LayoutLine] = []
    if framed:
        lines.append(LayoutLine(LineKind.HEADER, header_text(language, level)))
    by_path: dict[str, list[tuple[int, int]]] = {}
    ranked = sorted(
        enumerate(slice_.segments), key=lambda item: (item[1].path, item[1].region.start_line)
    )
    for index, segment in ranked:
        by_path.setdefault(segment.path, []).append((index, segment.region.start_line))
    first_file = True
    for path, members in by_path.items():
        if not first_file:
            lines.append(LayoutLine(LineKind.SEPARATOR, ""))
        first_file = False
        if framed:
            lines.append(LayoutLine(LineKind.LABEL, f"{prefix} {labels(path)}", path=path))
        previous_end: int | None = None
        for index, _ in members:
            segment = slice_.segments[index]
            if previous_end is not None and segment.region.start_line > previous_end + 1:
                lines.append(LayoutLine(LineKind.ELISION, marker, path=path))
            for offset, text in enumerate(split_lines(segment.text.expose())):
                lines.append(
                    LayoutLine(
                        LineKind.SEGMENT,
                        text,
                        path=path,
                        segment_index=index,
                        file_line=segment.region.start_line + offset,
                    )
                )
            previous_end = segment.region.end_line
    stubs = sorted(slice_.stubs, key=lambda stub: (stub.path or "", stub.line or 0, stub.symbol))
    if stubs:
        if lines:
            lines.append(LayoutLine(LineKind.SEPARATOR, ""))
        for stub in stubs:
            lines.extend(
                LayoutLine(LineKind.STUB, text) for text in stub.signature.expose().split("\n")
            )
    return PayloadLayout(language, tuple(lines))


class LineMapBuilder:
    """Builds the entries of ``SanitisedPayload.line_map`` from the layout of a slice."""

    @staticmethod
    def build(
        slice_: CodeSlice, payload_text: str, *, framed: bool = True
    ) -> tuple[LineMapEntry, ...]:
        """The line map of ``payload_text``, which must have the line structure of ``slice_``.

        Entries are ascending, do not overlap, stay within the text and are linear: a run of
        payload lines maps onto consecutive lines of one segment. Two adjacent segments give two
        entries.

        Raises:
            PseudonymError: the text has a different number of lines than the layout.
        """
        layout = layout_of(slice_, _FRAMED_LEVEL, framed=framed)
        return map_layout(layout, payload_text)


def map_layout(layout: PayloadLayout, payload_text: str) -> tuple[LineMapEntry, ...]:
    """The line map of ``payload_text`` for a ``layout`` it was built from."""
    if len(split_lines(payload_text)) != len(layout.lines):
        raise PseudonymError("the payload does not have the line structure of its slice")
    entries: list[LineMapEntry] = []
    open_entry: tuple[int, int, int, int] | None = None  # first, last, segment, first file line
    for number, line in enumerate(layout.lines, start=1):
        if line.kind is LineKind.SEGMENT and line.segment_index is not None:
            assert line.file_line is not None  # noqa: S101 - set together with segment_index
            if (
                open_entry is not None
                and open_entry[2] == line.segment_index
                and open_entry[1] == number - 1
            ):
                open_entry = (open_entry[0], number, open_entry[2], open_entry[3])
                continue
            if open_entry is not None:
                entries.append(_entry(open_entry))
            open_entry = (number, number, line.segment_index, line.file_line)
        elif open_entry is not None:
            entries.append(_entry(open_entry))
            open_entry = None
    if open_entry is not None:
        entries.append(_entry(open_entry))
    return tuple(entries)


def _entry(run: tuple[int, int, int, int]) -> LineMapEntry:
    return LineMapEntry(
        payload_start_line=run[0],
        payload_end_line=run[1],
        segment_index=run[2],
        file_start_line=run[3],
    )
