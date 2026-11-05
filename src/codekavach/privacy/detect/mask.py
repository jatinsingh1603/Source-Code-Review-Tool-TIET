"""Keep placeholders out of detection: ``mask_placeholders``.

Owning epic: E08.

After redaction a text holds tokens such as ``<PII:email:2>``. A second detection pass (the
guard's independent re-scan, E12-02) would see ``email`` inside that token, and a pseudonymiser
that renames identifiers (E09) would see ``SECRET`` as one. ``mask_placeholders`` blanks every
token to spaces of the **same length**, so byte offsets are unchanged, before detectors run;
:func:`placeholder_regions` returns where the tokens were so spans that reach into one can be
clipped. E09 reads the same pattern to treat a token as an opaque atom.
"""

import re
from typing import Final

from codekavach.core.models.payload import PLACEHOLDER_PATTERN

PLACEHOLDER_MASK_PATTERN: Final = re.compile(PLACEHOLDER_PATTERN)
FILLER: Final = " "


def mask_placeholders(text: str) -> str:
    """Return ``text`` with every placeholder token replaced by spaces of the same length."""
    return PLACEHOLDER_MASK_PATTERN.sub(lambda match: FILLER * len(match.group(0)), text)


def placeholder_regions(text: str) -> tuple[tuple[int, int], ...]:
    """The ``(start_byte, end_byte)`` of each placeholder token in ``text``.

    Tokens are ASCII, so a character offset inside one equals its byte offset; the offsets
    returned here are bytes of the whole UTF-8 text.
    """
    regions: list[tuple[int, int]] = []
    for match in PLACEHOLDER_MASK_PATTERN.finditer(text):
        start = len(text[: match.start()].encode("utf-8"))
        regions.append((start, start + len(match.group(0))))
    return tuple(regions)
