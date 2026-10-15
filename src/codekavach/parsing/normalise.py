r"""Unicode normalisation that must run before a file reaches the parser (E07-01).

Owning epic: E07.

Trojan Source (Boucher and Anderson, USENIX Security 2021) and the Unicode Tag technique
(Rehberger) show that bidirectional control characters, zero-width characters and Unicode Tag
characters change what a human reads in an editor while leaving what a compiler, and a triage
LLM reading the same bytes, sees unchanged; the same characters can carry hidden instructions to
a model (``docs/research/INSIGHTS.md`` section 7). This module is both a parsing precondition and
a privacy and injection control: nothing downstream of ``normalise_source`` ever sees one of
these characters again, but the characters are never silently dropped, because stripping shifts
every later byte offset and erases the evidence that something was hidden.

The M1 rule: replace each hidden character with a visible, length-preserving sentinel (one code
point in, one code point out) and attach a report of what was found and where. Raising the report
as a finding is a later epic's job (the rule engine, E16, and the prompt-injection defences,
E24); this module only detects, substitutes and reports.

Line endings are read, never rewritten, here: this module relies on ``LineIndex`` (which splits
on ``b"\\n"`` only, matching ``split_lines``) for locations, so a ``\\r\\n`` file needs no
separate handling and no byte is ever inserted or removed by this pass.
"""

import re
from enum import StrEnum

from codekavach.core.models import Location
from codekavach.parsing.positions import LineIndex

# Bidirectional control characters (Trojan Source): can reorder the glyphs a human reads without
# changing the underlying bytes a compiler or an LLM consumes.
_BIDI_CONTROL = range(0x202A, 0x202F)  # U+202A-U+202E
_BIDI_ISOLATE = range(0x2066, 0x206A)  # U+2066-U+2069
# Zero-width characters: invisible in a rendered editor.
_ZERO_WIDTH = range(0x200B, 0x200E)  # U+200B-U+200D
_BOM = 0xFEFF
# Unicode Tag characters (the ASCII Smuggler / Unicode Tag technique): invisible in every font.
_UNICODE_TAG = range(0xE0000, 0xE0080)

# Visible, length-preserving sentinels (one code point in, one code point out).
_ZERO_WIDTH_SENTINEL = "␣"  # OPEN BOX, for zero-width and Unicode Tag characters
_BIDI_SENTINEL = "·"  # MIDDLE DOT, for bidirectional control characters


class HiddenKind(StrEnum):
    """The class of hidden character found."""

    BIDI_CONTROL = "bidi_control"
    ZERO_WIDTH = "zero_width"
    UNICODE_TAG = "unicode_tag"


def _classify(char: str, index: int) -> HiddenKind | None:
    point = ord(char)
    if point in _BIDI_CONTROL or point in _BIDI_ISOLATE:
        return HiddenKind.BIDI_CONTROL
    if point in _UNICODE_TAG:
        return HiddenKind.UNICODE_TAG
    if point in _ZERO_WIDTH:
        return HiddenKind.ZERO_WIDTH
    if point == _BOM and index != 0:
        return HiddenKind.ZERO_WIDTH
    return None


def _sentinel_for(kind: HiddenKind) -> str:
    return _BIDI_SENTINEL if kind is HiddenKind.BIDI_CONTROL else _ZERO_WIDTH_SENTINEL


# A fast presence check, run before the precise per-character loop: ordinary source code has no
# character from any of these ranges, and most of a scan's files never reach the slow path.
# Over-matching the BOM-at-position-0 exemption here is fine; the exact loop decides that case.
# Built from chr() at import time, rather than as a literal character class, so the control
# characters it matches never appear as raw bytes in this source file (ruff PLE2502).
_HIDDEN_CHAR_RANGES = (
    _BIDI_CONTROL,
    _BIDI_ISOLATE,
    _ZERO_WIDTH,
    range(_BOM, _BOM + 1),
    _UNICODE_TAG,
)
_HIDDEN_CHAR_PATTERN = re.compile(
    "[" + "".join(f"{chr(r.start)}-{chr(r.stop - 1)}" for r in _HIDDEN_CHAR_RANGES) + "]"
)


class HiddenCharOccurrence:
    """One hidden character found, replaced and reported."""

    __slots__ = ("kind", "location")

    def __init__(self, kind: HiddenKind, location: Location) -> None:
        self.kind = kind
        self.location = location

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HiddenCharOccurrence):
            return NotImplemented
        return self.kind == other.kind and self.location == other.location

    def __hash__(self) -> int:
        return hash((self.kind, self.location))

    def __repr__(self) -> str:
        return f"HiddenCharOccurrence(kind={self.kind!r}, location={self.location.display()!r})"


class HiddenCharReport:
    """Every hidden character found in one file, in source order."""

    __slots__ = ("occurrences",)

    def __init__(self, occurrences: tuple[HiddenCharOccurrence, ...] = ()) -> None:
        self.occurrences = occurrences

    @property
    def count(self) -> int:
        """Total number of hidden characters found, across every kind."""
        return len(self.occurrences)

    def count_of(self, kind: HiddenKind) -> int:
        """Number of hidden characters found of one ``kind``."""
        return sum(1 for item in self.occurrences if item.kind is kind)

    def __bool__(self) -> bool:
        return bool(self.occurrences)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HiddenCharReport):
            return NotImplemented
        return self.occurrences == other.occurrences

    def __hash__(self) -> int:
        return hash(self.occurrences)


EMPTY_HIDDEN_CHAR_REPORT = HiddenCharReport()


def normalise_source(text: str, path: str) -> tuple[str, HiddenCharReport]:
    """Replace hidden characters in ``text`` with visible sentinels; never strip one silently.

    Returns ``(normalised_text, report)`` where ``len(normalised_text) == len(text)`` always,
    and ``report`` names the kind and ``Location`` of every occurrence, in source order. A file
    with no hidden character is returned unchanged (identity), and the same object is reused for
    its (empty) report.

    ``path`` labels the ``Location`` of each occurrence; pass the file's own repository path.
    """
    if _HIDDEN_CHAR_PATTERN.search(text) is None:
        return text, EMPTY_HIDDEN_CHAR_REPORT  # the common case: no per-character work at all

    kinds: list[tuple[int, int, HiddenKind]] = []  # (char index, byte offset, kind)
    for index, char in enumerate(text):
        kind = _classify(char, index)
        if kind is not None:
            # Occurrences are rare once the fast check above has matched, so an encode of the
            # prefix per occurrence is cheap; it is never done in the common no-match case.
            kinds.append((index, len(text[:index].encode("utf-8")), kind))
    if not kinds:
        return text, EMPTY_HIDDEN_CHAR_REPORT
    line_index = LineIndex.build(text)  # built once, before any substitution
    chars = list(text)
    occurrences: list[HiddenCharOccurrence] = []
    for index, offset, kind in kinds:
        chars[index] = _sentinel_for(kind)
        line, column = line_index.position(offset)
        location = Location(
            path=path, start_line=line, end_line=line, start_col=column, end_col=column + 1
        )
        occurrences.append(HiddenCharOccurrence(kind, location))
    return "".join(chars), HiddenCharReport(tuple(occurrences))
