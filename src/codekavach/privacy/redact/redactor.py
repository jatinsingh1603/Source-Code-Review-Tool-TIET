"""``Redactor``: replace detected spans with typed placeholders, consistently.

Owning epic: E08.

Spans are byte offsets into the UTF-8 text. The text is encoded once and cut by those offsets, so
no character-index conversion happens per span, and every boundary is checked to fall on a
character boundary: a span that starts or ends inside a multi-byte character would cut a
character in two and is refused (fail closed, I4). Nothing partial is ever returned; any problem
raises :class:`~codekavach.privacy.errors.RedactionError`, which makes the caller abort the
candidate.

The output is built left to right, in one pass, so indices are assigned in text order and the
result is the same as substituting from the last span backwards. The declared ``placeholders`` are
**counted from the text that was produced**, not taken from the span list: a span that overlap
resolution dropped is then never declared without appearing, and a token already present in the
input (a text redacted before) is declared too, which is what ``SanitisedPayload`` checks in both
directions.

A placeholder keeps the line breaks of the value it replaces (a PEM private key spans several
lines): they follow the token, so the redacted text has the line structure of its input and the
payload's line map still points at the source lines. Without that, every candidate in a file
with a multi-line secret failed pseudonymisation and was never reviewed.
"""

import re
from collections.abc import Sequence
from typing import ClassVar

from pydantic import Field

from codekavach.core.models import DataClassification, KavachModel, PlaceholderRef
from codekavach.core.models.payload import find_placeholders, format_placeholder, parse_placeholder
from codekavach.privacy.detect.base import TypedSpan
from codekavach.privacy.errors import RedactionError
from codekavach.privacy.redact.numbering import PlaceholderNumbering

_CONTINUATION_MASK = 0xC0
_CONTINUATION = 0x80


class RedactionResult(KavachModel):
    """Redacted text with the placeholders it contains.

    ``text`` is still client code with its names (pseudonymisation, E09, comes next), so the
    model is ``RAW`` and ``text`` is kept out of ``repr``.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    text: str = Field(repr=False)
    placeholders: tuple[PlaceholderRef, ...] = ()
    spans_applied: int = Field(default=0, ge=0)


def _on_boundary(data: bytes, offset: int) -> bool:
    return offset in (0, len(data)) or (data[offset] & _CONTINUATION_MASK) != _CONTINUATION


def _declared(text: str) -> tuple[PlaceholderRef, ...]:
    """One :class:`PlaceholderRef` per distinct token of ``text``, in order of first appearance."""
    counts: dict[str, int] = {}
    for token in find_placeholders(text):
        counts[token] = counts.get(token, 0) + 1
    refs: list[PlaceholderRef] = []
    for token, occurrences in counts.items():
        kind, subtype, index = parse_placeholder(token)
        refs.append(
            PlaceholderRef(
                token=token, kind=kind, subtype=subtype, index=index, occurrences=occurrences
            )
        )
    return tuple(refs)


_LINE_BREAK = re.compile(r"\r?\n")


class Redactor:
    """Turns text and spans into a :class:`RedactionResult`."""

    def redact(
        self, text: str, spans: Sequence[TypedSpan], *, numbering: PlaceholderNumbering
    ) -> RedactionResult:
        """Replace each span of ``text`` with its placeholder.

        Raises:
            RedactionError: a span is out of range, overlaps another, starts or ends inside a
                character, produces a token that is already in the text, or exhausts the index
                space; or the text cannot be encoded.
        """
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError:
            raise RedactionError("the text is not valid Unicode") from None
        ordered = sorted(spans, key=lambda s: (s.start_byte, s.end_byte))
        existing = set(find_placeholders(text))
        chunks: list[bytes] = []
        position = 0
        for span in ordered:
            if span.end_byte > len(data):
                raise RedactionError("a span reaches beyond the text")
            if span.start_byte < position:
                raise RedactionError("spans overlap")
            if not (_on_boundary(data, span.start_byte) and _on_boundary(data, span.end_byte)):
                raise RedactionError("a span boundary falls inside a character")
            value = data[span.start_byte : span.end_byte].decode("utf-8")
            index = numbering.index_for(span.kind, span.subtype, value)
            token = format_placeholder(span.kind, span.subtype, index)
            if token in existing:
                raise RedactionError("a placeholder already in the text would be reused")
            chunks.append(data[position : span.start_byte])
            chunks.append(token.encode("ascii"))
            chunks.append("".join(_LINE_BREAK.findall(value)).encode("ascii"))
            position = span.end_byte
        chunks.append(data[position:])
        result = b"".join(chunks).decode("utf-8")
        return RedactionResult(
            text=result, placeholders=_declared(result), spans_applied=len(ordered)
        )
