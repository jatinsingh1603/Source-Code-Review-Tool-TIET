"""Comment and docstring blanking: remove them from a payload without moving a single line.

Owning epic: E09. Issue E09-03. Normative layout: docs/ARCHITECTURE.md section 3.

Every comment and docstring is replaced by the same number of UTF-8 bytes of spaces, and every
newline stays where it was, so the line map of the payload stays a linear function inside each
slice segment (``SanitisedPayload.map_line``, E02-12) and every byte offset after the blanked
region is unchanged. A docstring is the one syntactically significant form: a Python docstring is
a string expression statement, so blanking it to spaces would leave an empty expression. It is
replaced instead by a string literal of the same length whose body is the marker character, with
the original quotes and string prefix kept, so the file still parses.

**What this does and does not do.** Comments are an injection channel: adversarial text placed in
a comment has steered reviewers and pipelines (docs/research/INSIGHTS.md insight 6 and section 7).
At this level comments do not reach the model at all, which removes that particular channel. This
module makes no claim to prevent prompt injection in general; the defence suite belongs to a later
milestone.

A placeholder token left by E08 inside a comment is never blanked: it is kept byte for byte, so
the redaction record stays intact.

The span kind is read from the text, not from the caller: a span whose text begins with a quote
(after an optional string prefix) is a docstring, anything else is a comment.
"""

import re
from collections.abc import Sequence
from typing import Final

from codekavach.core.models import Location
from codekavach.privacy.detect.mask import PLACEHOLDER_MASK_PATTERN
from codekavach.privacy.errors import PseudonymError

_STRING_PREFIX: Final = re.compile(r"^[rRbBuUfF]{0,2}")
_TRIPLE: Final = ('"""', "'''")
_FORBIDDEN_MARKER: Final = frozenset("\"'\\\n\r\t ")


def _check_marker(marker: str) -> None:
    if len(marker) != 1 or marker in _FORBIDDEN_MARKER or not marker.isprintable():
        raise PseudonymError("the blanking marker is one printable character, not a quote")


def _offsets(text: str, spans: Sequence[Location]) -> list[tuple[int, int]]:
    """Character offsets of each span, from 1-based line and code-point columns."""
    line_starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            line_starts.append(index + 1)
    ranges: list[tuple[int, int]] = []
    for span in spans:
        if span.start_line > len(line_starts):
            raise PseudonymError("a comment span starts beyond the text")
        start_line_begin = line_starts[span.start_line - 1]
        if span.start_col is None or span.end_col is None:
            # Whole lines: from the start of the first line to the newline that ends the last.
            if span.end_line > len(line_starts):
                raise PseudonymError("a comment span ends beyond the text")
            end = line_starts[span.end_line] - 1 if span.end_line < len(line_starts) else len(text)
            ranges.append((start_line_begin, end))
            continue
        if span.end_line > len(line_starts):
            raise PseudonymError("a comment span ends beyond the text")
        begin = start_line_begin + span.start_col - 1
        end = line_starts[span.end_line - 1] + span.end_col - 1
        if end > len(text) or begin > end:
            raise PseudonymError("a comment span lies outside the text")
        ranges.append((begin, end))
    return ranges


def _blank_chars(text: str, *, filler: str) -> str:
    """Replace each character by ``filler`` repeated once per UTF-8 byte; newlines are kept."""
    out: list[str] = []
    for char in text:
        if char == "\n":
            out.append("\n")
        else:
            out.append(filler * len(char.encode("utf-8")))
    return "".join(out)


def _placeholders(text: str) -> list[str]:
    return [match.group(0) for match in PLACEHOLDER_MASK_PATTERN.finditer(text)]


def _split_placeholders(text: str) -> list[tuple[str, bool]]:
    """The text as alternating (chunk, is_placeholder) pieces, placeholders kept whole."""
    pieces: list[tuple[str, bool]] = []
    position = 0
    for match in PLACEHOLDER_MASK_PATTERN.finditer(text):
        if match.start() > position:
            pieces.append((text[position : match.start()], False))
        pieces.append((match.group(0), True))
        position = match.end()
    if position < len(text):
        pieces.append((text[position:], False))
    return pieces


def _blank_span(text: str, *, marker: str) -> str:
    """One comment or docstring, blanked; placeholder tokens inside it are kept verbatim."""
    prefix = _STRING_PREFIX.match(text)
    body_start = prefix.end() if prefix else 0
    rest = text[body_start:]
    if not rest or rest[0] not in "\"'":
        return "".join(
            chunk if is_placeholder else _blank_chars(chunk, filler=" ")
            for chunk, is_placeholder in _split_placeholders(text)
        )
    quote = rest[:3] if rest.startswith(_TRIPLE) else rest[0]
    if len(text) < body_start + 2 * len(quote) or not text.endswith(quote):
        raise PseudonymError("a docstring span has no closing quote")
    head = text[: body_start + len(quote)]
    tail = text[len(text) - len(quote) :]
    body = text[len(head) : len(text) - len(tail)]
    blanked_body = "".join(
        chunk if is_placeholder else _blank_chars(chunk, filler=marker)
        for chunk, is_placeholder in _split_placeholders(body)
    )
    return head + blanked_body + tail


def blank_comments(text: str, spans: Sequence[Location], *, marker: str) -> str:
    """Return ``text`` with every span replaced, newlines and byte offsets preserved.

    A comment span becomes spaces. A docstring span (its text begins with a quote) becomes a
    string literal of the same length whose body is ``marker`` repeated, so the file still parses.
    ``marker`` is one printable character that is neither a quote, a backslash nor whitespace.

    Raises:
        PseudonymError: the marker is invalid, or a span lies outside the text or has no closing
            quote. Nothing is returned in that case, so the caller aborts (fail closed, I4).
    """
    _check_marker(marker)
    if not spans:
        return text
    ranges = sorted(_offsets(text, spans))
    out: list[str] = []
    position = 0
    for begin, end in ranges:
        if begin < position:
            raise PseudonymError("comment spans overlap")
        out.append(text[position:begin])
        out.append(_blank_span(text[begin:end], marker=marker))
        position = end
    out.append(text[position:])
    result = "".join(out)
    if _placeholders(text) != _placeholders(result):
        raise PseudonymError("a placeholder token was lost while blanking")
    return result
