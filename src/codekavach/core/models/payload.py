"""SanitisedPayload: what an LLM may see, and the only code-bearing input of codekavach.llm.

Owning epic: E02.

The three models here are structurally unable to carry original client data: there is no path,
original identifier, original value, Location, Candidate or RawCode field anywhere, and a schema
test rejects such property names. ``line_map`` refers to ``CodeSlice.segments[segment_index]``;
the slice itself stays inside the privacy layer (E02-01 ADR, decision D9). The model does not
prove that the text is clean; that is the egress guard's job (E12).

``payload_hash`` is SHA-256 of the text alone, so the same input with the same scan salt gives
the same hash and a cache hit (invariant I5); the random ``id`` is not part of it.

L0 note: at L0 nothing leaves the machine, but a local model inside the trust boundary still
receives its input through codekavach.llm. A payload with ``level = L0`` and unmodified code
wrapped as SanitisedText is therefore legitimate. Whether a provider may receive a level is
decided by policy and the egress transport (E12, E25), not by this model.
"""

import re
from collections import Counter
from typing import ClassVar, Self

from pydantic import Field, model_validator

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PlaceholderKind, PrivacyLevel
from codekavach.core.models.ids import (
    CandidateId,
    CandidateIdField,
    PayloadIdField,
    SliceId,
    SliceIdField,
    new_payload_id,
)
from codekavach.core.models.text import SanitisedText

PLACEHOLDER_PATTERN = r"<(SECRET|PII|TERM):([a-z][a-z0-9_]{0,47}):([1-9][0-9]{0,5})>"
_PLACEHOLDER = re.compile(PLACEHOLDER_PATTERN)
_SUBTYPE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")


def format_placeholder(kind: PlaceholderKind, subtype: str, index: int) -> str:
    """Return the placeholder token, for example ``<SECRET:aws_access_key:1>``."""
    token = f"<{kind.value}:{subtype}:{index}>"
    if not _PLACEHOLDER.fullmatch(token):
        raise ValueError("invalid placeholder subtype or index")
    return token


def parse_placeholder(token: str) -> tuple[PlaceholderKind, str, int]:
    """Return ``(kind, subtype, index)`` of a placeholder token."""
    match = _PLACEHOLDER.fullmatch(token)
    if not match:
        raise ValueError("not a placeholder token")
    return PlaceholderKind(match.group(1)), match.group(2), int(match.group(3))


def find_placeholders(text: str) -> list[str]:
    """Return every placeholder token in ``text``, in order, with repetitions."""
    return [match.group(0) for match in _PLACEHOLDER.finditer(text)]


class PlaceholderRef(KavachModel):
    """One distinct placeholder in a payload: its type is evidence, its value is not kept."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.SANITISED

    token: str
    kind: PlaceholderKind
    subtype: str = Field(
        description=(
            "Detector type from the closed vocabulary owned by E08 (aws_access_key, email, "
            "domain, ...). Never derived from the matched text."
        )
    )
    index: int = Field(ge=1, le=999_999)
    occurrences: int = Field(ge=1)

    @model_validator(mode="after")
    def _check_token(self) -> Self:
        if not _SUBTYPE.match(self.subtype):
            raise ValueError("subtype must be a lower-case detector type name")
        if self.token != format_placeholder(self.kind, self.subtype, self.index):
            raise ValueError("token does not match kind, subtype and index")
        return self


class LineMapEntry(KavachModel):
    """A run of payload lines that maps linearly onto lines of one slice segment."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.SANITISED

    payload_start_line: int = Field(ge=1)
    payload_end_line: int = Field(ge=1)
    segment_index: int = Field(ge=0)
    file_start_line: int = Field(ge=1)

    @model_validator(mode="after")
    def _check_order(self) -> Self:
        if self.payload_end_line < self.payload_start_line:
            raise ValueError("payload_end_line must not be before payload_start_line")
        return self


class SanitisedPayload(VersionedModel):
    """What the LLM may see for one candidate."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.SANITISED
    SCHEMA_VERSION: ClassVar[int] = 1

    id: PayloadIdField
    candidate_id: CandidateIdField
    slice_id: SliceIdField | None
    text: SanitisedText
    level: PrivacyLevel
    placeholders: tuple[PlaceholderRef, ...] = ()
    pseudonym_count: int = Field(default=0, ge=0)
    line_map: tuple[LineMapEntry, ...] = ()
    payload_hash: str

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        text = self.text.expose()
        if self.payload_hash != sha256_hex(text):
            raise ValueError("payload_hash does not match the text")
        self._check_placeholders(text)
        self._check_line_map()
        if self.level is PrivacyLevel.L4:
            if self.line_map:
                raise ValueError("an L4 payload carries no code lines, so line_map must be empty")
        elif self.slice_id is None:
            raise ValueError("slice_id is required unless the level is L4")
        return self

    def _check_placeholders(self, text: str) -> None:
        found = Counter(find_placeholders(text))
        declared = [ref.token for ref in self.placeholders]
        if len(set(declared)) != len(declared):
            raise ValueError("each placeholder must be declared exactly once")
        if set(declared) != set(found):
            raise ValueError("declared placeholders and placeholders in the text differ")
        for ref in self.placeholders:
            if ref.occurrences != found[ref.token]:
                raise ValueError("placeholder occurrences do not match the text")

    def _check_line_map(self) -> None:
        previous_end = 0
        for entry in self.line_map:
            if entry.payload_start_line <= previous_end:
                raise ValueError("line_map entries must be ascending and must not overlap")
            previous_end = entry.payload_end_line
        if previous_end > self.text.line_count:
            raise ValueError("line_map reaches beyond the last line of the text")

    def map_line(self, payload_line: int) -> tuple[int, int] | None:
        """Return ``(segment_index, file_line)`` for a payload line, or None if unmapped."""
        for entry in self.line_map:
            if entry.payload_start_line <= payload_line <= entry.payload_end_line:
                offset = payload_line - entry.payload_start_line
                return entry.segment_index, entry.file_start_line + offset
        return None

    @classmethod
    def build(
        cls,
        *,
        candidate_id: CandidateId,
        slice_id: SliceId | None,
        text: SanitisedText,
        level: PrivacyLevel,
        pseudonym_count: int = 0,
        line_map: tuple[LineMapEntry, ...] = (),
    ) -> Self:
        """Build a payload, deriving ``id``, ``placeholders`` and ``payload_hash``."""
        raw = text.expose()
        counts = Counter(find_placeholders(raw))
        placeholders = []
        for token in dict.fromkeys(find_placeholders(raw)):
            kind, subtype, index = parse_placeholder(token)
            placeholders.append(
                PlaceholderRef(
                    token=token,
                    kind=kind,
                    subtype=subtype,
                    index=index,
                    occurrences=counts[token],
                )
            )
        return cls(
            id=new_payload_id(),
            candidate_id=candidate_id,
            slice_id=slice_id,
            text=text,
            level=level,
            placeholders=tuple(placeholders),
            pseudonym_count=pseudonym_count,
            line_map=line_map,
            payload_hash=sha256_hex(raw),
        )
