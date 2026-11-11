"""Small text helpers shared by the SARIF modules.

Owning epic: E14.
"""

import unicodedata

ELLIPSIS = "…"


def truncate_at_word(text: str, limit: int) -> str:
    """Return ``text`` cut to at most ``limit`` characters at a word boundary, ending in ``…``."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    boundary = cut.rfind(" ")
    if boundary > limit // 2:
        cut = cut[:boundary]
    return cut.rstrip(" \t,;:.") + ELLIPSIS


def strip_controls(text: str, *, keep: str = "\n\t") -> str:
    """Remove control characters other than those in ``keep`` (text is never interpreted)."""
    return "".join(c for c in text if c in keep or unicodedata.category(c) != "Cc")


def clean_text(text: str, limit: int) -> str:
    """Control characters removed, surrounding space stripped, cut at a word boundary."""
    return truncate_at_word(strip_controls(text).strip(), limit)
