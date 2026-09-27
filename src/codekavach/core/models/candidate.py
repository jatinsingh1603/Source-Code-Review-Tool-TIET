"""Candidate: output of deterministic analysis and input to the privacy layer.

Owning epic: E02. A candidate holds raw client data (paths, symbols, engine messages quoting
code). Under invariant I2 it is never accepted by codekavach.llm; only the privacy layer reads
it. Its random ``id`` is the only attribute that appears in an EgressRecord.
"""

import re
import unicodedata
from typing import Any, ClassVar, Self

from pydantic import Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, VersionedModel
from codekavach.core.models.enums import CandidateKind, Confidence, Language, Severity
from codekavach.core.models.ids import CandidateIdField, new_candidate_id
from codekavach.core.models.location import Location
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.taxonomy import CweId, parse_cwe

MAX_MESSAGE_LENGTH = 2000
MAX_PROPERTIES = 32
MAX_PROPERTY_VALUE_LENGTH = 500
FINGERPRINT_PATTERN = r"^ckfp1:[0-9a-f]{32}$"

_ENGINE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_PROPERTY_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class Candidate(VersionedModel):
    """A possible weakness reported by an engine, rule or detector."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW
    SCHEMA_VERSION: ClassVar[int] = 1

    id: CandidateIdField
    rule_id: str = Field(min_length=1, max_length=256)
    engine: str
    cwe: tuple[CweId, ...] = ()
    locations: tuple[Location, ...] = Field(min_length=1)
    taint_path: TaintPath | None = None
    engine_severity: Severity | None = None
    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    kind: CandidateKind = CandidateKind.VULNERABILITY
    language: Language = Language.UNKNOWN
    message: str = Field(
        default="",
        max_length=MAX_MESSAGE_LENGTH,
        description=(
            "Engine message; local only. For secret candidates it must never contain the "
            "secret value."
        ),
    )
    engine_version: str | None = None
    engine_confidence: Confidence | None = None
    properties: tuple[tuple[str, str], ...] = Field(
        default=(),
        max_length=MAX_PROPERTIES,
        description=(
            "Engine-specific key and value pairs; local only. For secret candidates they must "
            "never contain the secret value."
        ),
    )

    @field_validator("engine")
    @classmethod
    def _check_engine(cls, value: str) -> str:
        if not _ENGINE.match(value):
            raise ValueError("engine must be a lower-case slug of 1 to 64 characters")
        return value

    @field_validator("rule_id")
    @classmethod
    def _check_rule_id(cls, value: str) -> str:
        if any(char.isspace() or unicodedata.category(char) == "Cc" for char in value):
            raise ValueError("rule_id must not contain whitespace or control characters")
        return value

    @field_validator("cwe", mode="before")
    @classmethod
    def _dedupe_cwe(cls, value: Any) -> Any:
        if isinstance(value, list | tuple):
            seen: dict[int, None] = {}
            for item in value:
                seen.setdefault(parse_cwe(item), None)
            return tuple(seen)
        return value

    @field_validator("properties")
    @classmethod
    def _check_properties(cls, value: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        keys = [key for key, _ in value]
        if len(set(keys)) != len(keys):
            raise ValueError("property keys must be unique")
        for key, item in value:
            if not _PROPERTY_KEY.match(key):
                raise ValueError("property keys must be lower-case identifiers of 1 to 64 chars")
            if len(item) > MAX_PROPERTY_VALUE_LENGTH:
                raise ValueError("property values must be at most 500 characters")
        return value

    @model_validator(mode="after")
    def _check_taint_sink(self) -> Self:
        if self.taint_path is not None:
            sink_path = self.taint_path.sink.location.path
            if all(location.path != sink_path for location in self.locations):
                raise ValueError("the taint path's sink file must be one of the locations")
        return self

    @property
    def primary_location(self) -> Location:
        """The first location, where the engine reported the result."""
        return self.locations[0]

    @property
    def primary_cwe(self) -> int | None:
        """The first CWE, or None."""
        return self.cwe[0] if self.cwe else None

    @property
    def files(self) -> tuple[str, ...]:
        """Distinct paths over the locations and the taint path, in first-seen order."""
        paths = [location.path for location in self.locations]
        if self.taint_path is not None:
            paths.extend(self.taint_path.files)
        return tuple(dict.fromkeys(paths))

    @classmethod
    def create(cls, **fields: Any) -> Self:
        """Validate ``fields`` into a candidate, generating an id when none is given."""
        if "id" not in fields:
            fields["id"] = new_candidate_id()
        return cls.model_validate(fields)
