"""Elision markers and elided text.

Owning epic: E11.

A removed region is replaced by one comment line, never by a bare ``...``: a comment parses in every
language and cannot be mistaken for code by a model or by the renamer (E09). The marker starts at
column 0, so it never changes the indentation the surrounding lines rely on.

Syntactic coherence (the rule the slicing strategies keep and the tests check by re-parsing):

* a segment starts at the beginning of a statement or declaration and ends at the end of one;
* when a block is cut, its opening line and its closing token stay in place, with one marker
  between them (the strategies keep the header lines of a compound statement and, in languages
  with braces, its closing line);
* a segment inside a class or function keeps the container's header as a context segment, so the
  indented code that follows it parses.

``elide_region`` is the text-level form of the rule: given the lines of a region and the line
ranges to keep, it returns the kept lines with one marker for every removed stretch.
"""

from collections.abc import Sequence
from typing import Final

from codekavach.core.models import Language

_HASH_COMMENT: Final = "# ... elided ..."
_SLASH_COMMENT: Final = "// ... elided ..."
_BY_LANGUAGE: Final = {
    Language.PYTHON: _HASH_COMMENT,
    Language.JAVASCRIPT: _SLASH_COMMENT,
    Language.TYPESCRIPT: _SLASH_COMMENT,
    Language.JAVA: _SLASH_COMMENT,
    Language.GO: _SLASH_COMMENT,
}


def elision_marker(language: Language) -> str:
    """The comment line that stands for removed code in ``language``.

    Raises:
        ValueError: ``language`` has no comment form registered here.
    """
    try:
        return _BY_LANGUAGE[language]
    except KeyError:
        raise ValueError(f"no elision marker for language {language.value!r}") from None


def supported(language: Language) -> bool:
    """Whether slices of ``language`` can be assembled."""
    return language in _BY_LANGUAGE


def comment_prefix(language: Language) -> str:
    """The line-comment opener of ``language`` (``#`` or ``//``)."""
    return elision_marker(language).split(" ", 1)[0]


def elide_region(text: str, keep_ranges: Sequence[tuple[int, int]], language: Language) -> str:
    """``text`` with every line outside ``keep_ranges`` replaced by one marker per stretch.

    ``keep_ranges`` are 1-based inclusive line ranges of ``text``. They may overlap, be given in
    any order or reach outside the text (they are clamped). Kept lines keep their order and
    content; a stretch of removed lines, before, between or after kept lines, becomes one marker.
    With nothing to keep the whole text becomes a single marker.
    """
    marker = elision_marker(language)
    lines = text.split("\n")
    keep = [False] * len(lines)
    for start, end in keep_ranges:
        for number in range(max(start, 1), min(end, len(lines)) + 1):
            keep[number - 1] = True
    out: list[str] = []
    in_gap = False
    for line, kept in zip(lines, keep, strict=True):
        if kept:
            out.append(line)
            in_gap = False
        elif not in_gap:
            out.append(marker)
            in_gap = True
    return "\n".join(out)
