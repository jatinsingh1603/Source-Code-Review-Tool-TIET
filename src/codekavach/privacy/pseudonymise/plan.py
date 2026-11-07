"""The rename plan: every byte-range edit of one source, validated before any text is produced.

Owning epic: E09. Issue E09-04. Normative layout: docs/ARCHITECTURE.md section 3.

Identifiers, literals and comments all rewrite byte ranges of the same source. Three passes would
each invalidate the next pass's offsets, so one plan is built from the original, checked, and
applied once from the end backwards (``apply.apply_plan``). A plan that does not pass the check
raises ``PseudonymError`` before a single character of output exists, so the candidate fails
closed (I4) instead of carrying half-renamed code.

The checks: edits are sorted ascending, no two overlap (the error names both reasons), every edit
falls on character boundaries of the UTF-8 source, and no edit touches a byte inside a placeholder
token left by E08. A repr shows counts, never text.
"""

import zlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from codekavach.privacy.detect.mask import PLACEHOLDER_MASK_PATTERN
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator, PseudonymKind


class EditReason(StrEnum):
    """Why a range is rewritten; two reasons claiming the same bytes is a loud error."""

    IDENTIFIER = "identifier"
    SHORTHAND_KEY = "shorthand_key"
    LITERAL = "literal"
    COMMENT = "comment"
    NAME_STRING = "name_string"


@dataclass(frozen=True, slots=True)
class RenameEdit:
    """Replace ``source[start_byte:end_byte]`` (UTF-8 bytes) by ``replacement``.

    An insertion has ``start_byte == end_byte``. ``replacement`` is a token, a shaped literal or
    blanks, never original code.
    """

    start_byte: int
    end_byte: int
    replacement: str
    reason: EditReason

    def __post_init__(self) -> None:
        if self.start_byte < 0 or self.end_byte < self.start_byte:
            raise PseudonymError("an edit has a negative or inverted byte range")


def placeholder_byte_ranges(source: bytes) -> tuple[tuple[int, int], ...]:
    """The byte range of every E08 placeholder token in ``source``."""
    text = source.decode("utf-8", errors="surrogateescape")
    if "<" not in text:
        return ()
    ranges: list[tuple[int, int]] = []
    for match in PLACEHOLDER_MASK_PATTERN.finditer(text):
        start = len(text[: match.start()].encode("utf-8", errors="surrogateescape"))
        ranges.append((start, start + len(match.group(0).encode("utf-8"))))
    return tuple(ranges)


def _is_boundary(source: bytes, offset: int) -> bool:
    """True when ``offset`` does not fall inside a multi-byte UTF-8 character."""
    if offset in (0, len(source)):
        return True
    return (source[offset] & 0xC0) != 0x80


@dataclass(frozen=True, slots=True)
class RenamePlan:
    """The edits of one source, sorted ascending by start byte."""

    edits: tuple[RenameEdit, ...] = field(default=())
    # (length, crc32) of the source this plan was validated against, so that applying a plan
    # that ``build`` already checked does not check it again.
    checked: tuple[int, int] | None = field(default=None, compare=False, repr=False)

    def __repr__(self) -> str:
        return f"RenamePlan(edits={len(self.edits)})"

    @classmethod
    def build(
        cls,
        identifiers: Iterable[RenameEdit],
        literals: Iterable[RenameEdit],
        comments: Iterable[RenameEdit],
        *,
        source: bytes | None = None,
    ) -> "RenamePlan":
        """One plan from the three kinds of edit; sorted, and validated when ``source`` is given.

        Raises:
            PseudonymError: the edits overlap, or (with ``source``) do not fit it.
        """
        merged = sorted(
            (*identifiers, *literals, *comments),
            key=lambda edit: (edit.start_byte, edit.end_byte),
        )
        plan = cls(tuple(merged))
        if source is not None:
            plan.validate(source)
            plan = cls(plan.edits, (len(source), zlib.crc32(source)))
        return plan

    def validate(self, source: bytes) -> None:
        """Check the plan against ``source``; raise before any text is produced.

        Raises:
            PseudonymError: edits are unsorted or overlap (naming both reasons), lie outside the
                source, split a multi-byte character, or touch a placeholder token.
        """
        if self.checked == (len(source), zlib.crc32(source)):
            return
        ascii_only = source.isascii()
        previous: RenameEdit | None = None
        for edit in self.edits:
            if edit.end_byte > len(source):
                raise PseudonymError("an edit lies beyond the end of the source")
            if previous is not None:
                if edit.start_byte < previous.start_byte:
                    raise PseudonymError("the edits are not sorted ascending")
                if edit.start_byte < previous.end_byte or (
                    edit.start_byte == previous.start_byte and edit.end_byte == previous.end_byte
                ):
                    raise PseudonymError(
                        f"two edits overlap: {previous.reason.value} and {edit.reason.value}"
                    )
            if not ascii_only and not (
                _is_boundary(source, edit.start_byte) and _is_boundary(source, edit.end_byte)
            ):
                raise PseudonymError("an edit would split a multi-byte character")
            previous = edit
        self._check_placeholders(source)

    def _check_placeholders(self, source: bytes) -> None:
        regions = placeholder_byte_ranges(source)
        index = 0
        for edit in self.edits:
            while index < len(regions) and regions[index][1] <= edit.start_byte:
                index += 1
            if index == len(regions):
                return
            start, _ = regions[index]
            # Here the token ends after the edit starts. An insertion touches it only strictly
            # inside; a range touches it when it reaches past the token's first byte.
            inside = (
                start < edit.start_byte
                if edit.start_byte == edit.end_byte
                else edit.end_byte > start
            )
            if inside:
                raise PseudonymError("an edit touches a placeholder token")


def edits_around_placeholders(
    start_byte: int, original: str, replacement: str, reason: EditReason
) -> list[RenameEdit]:
    """Edits that turn ``original`` into ``replacement`` while leaving each placeholder alone.

    A shaper keeps a placeholder token byte for byte, so original and replacement hold the same
    tokens in the same order. The text between them is replaced piece by piece and a piece that
    did not change produces no edit, so no edit ever covers a token.

    Raises:
        PseudonymError: the replacement does not carry the same placeholders (fail closed).
    """
    if "<" not in original and "<" not in replacement:
        if original == replacement:
            return []
        return [
            RenameEdit(start_byte, start_byte + len(original.encode("utf-8")), replacement, reason)
        ]
    before = list(PLACEHOLDER_MASK_PATTERN.finditer(original))
    after = list(PLACEHOLDER_MASK_PATTERN.finditer(replacement))
    if [m.group(0) for m in before] != [m.group(0) for m in after]:
        raise PseudonymError("a replacement does not keep the placeholder tokens of its range")
    edits: list[RenameEdit] = []
    cursor_old = cursor_new = 0
    offset = start_byte

    def piece(old_end: int, new_end: int) -> None:
        nonlocal offset
        old, new = original[cursor_old:old_end], replacement[cursor_new:new_end]
        size = len(old.encode("utf-8"))
        if old != new:
            edits.append(RenameEdit(offset, offset + size, new, reason))
        offset += size

    for old_match, new_match in zip(before, after, strict=True):
        piece(old_match.start(), new_match.start())
        offset += len(old_match.group(0).encode("utf-8"))
        cursor_old, cursor_new = old_match.end(), new_match.end()
    piece(len(original), len(replacement))
    return edits


def total_bytes(edits: Sequence[RenameEdit]) -> int:
    """The number of bytes the edits replace; used by tests and counters."""
    return sum(edit.end_byte - edit.start_byte for edit in edits)


def file_labels(generator: PseudonymGenerator, paths: Iterable[str]) -> dict[str, str]:
    """The ``file_N`` label of each slice file; a payload never carries a real path.

    The labels are numbered together, in HMAC order, so they depend on the scan salt and the set
    of paths and not on the order the files were met (I5). A module path inside the code is
    rewritten by the literal shaper (path segments become ``file_N`` or ``mod_N``) and by the
    renamer (an imported module is a ``mod_N`` name), through the same plan.
    """
    unique = sorted(set(paths))
    generator.prepare(PseudonymKind.FILE, unique)
    return {path: generator.token(PseudonymKind.FILE, path) for path in unique}
