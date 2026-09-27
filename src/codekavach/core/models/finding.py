"""Finding: the final, restored and rated result that reports and integrations consume.

Owning epic: E02.

A finding is fully restored client data (real identifiers in its text) and must never reach
codekavach.llm (invariant I2); the ``summarise`` task works from aggregated, non-code facts.
Provenance records ledger sequence numbers and candidate ids only, never vault content or
pseudonym mappings (I3), and ``LLMReviewRef.reasoning`` holds restored text only, so a finding
cannot be used to rebuild the mapping pair by pair. The model holds the rating fields but does
not compute them (E29), and does not cross-check severity against CVSS or the risk matrix.
"""

import re
from typing import ClassVar, Self

from pydantic import Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.enums import (
    CandidateKind,
    Confidence,
    DetectionOrigin,
    FindingStatus,
    Language,
    PrivacyLevel,
    Severity,
)
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.fingerprint import CORRELATION_PATTERN, FINGERPRINT_PATTERN
from codekavach.core.models.ids import CandidateIdField, FindingIdField, ScanIdField
from codekavach.core.models.lifecycle import StatusChange, apply_transition
from codekavach.core.models.location import Location
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.taxonomy import CweId, Reference, TaxonomyRef
from codekavach.core.models.timeutil import UtcDatetime

CVSS4_VECTOR_PATTERN = r"^CVSS:4\.0(/[A-Za-z]{1,3}:[A-Za-z])+$"
_CVSS4 = re.compile(CVSS4_VECTOR_PATTERN)


class Impact(KavachModel):
    """Impact on the five-by-five risk matrix, with a narrative."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    level: int = Field(ge=1, le=5)
    narrative: str = Field(default="", max_length=4000)


class Likelihood(KavachModel):
    """Likelihood on the five-by-five risk matrix, with a rationale."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    level: int = Field(ge=1, le=5)
    rationale: str = Field(default="", max_length=2000)


class EngineRef(KavachModel):
    """An engine rule that reported the finding."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    engine: str = Field(min_length=1, max_length=64)
    rule_id: str = Field(min_length=1, max_length=256)
    engine_version: str | None = None


class LLMReviewRef(KavachModel):
    """One LLM review of the finding, shown to the auditor; it never changes the status."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    task: str = Field(min_length=1, max_length=64)
    prompt_version: str | None = None
    level: PrivacyLevel
    ledger_seq: int | None = Field(default=None, ge=0)
    is_vulnerable: bool | None
    confidence: Confidence
    reasoning: str = Field(
        default="",
        max_length=4000,
        description="The model's reasoning after restoration to real names; never pseudonymised.",
    )


class Provenance(KavachModel):
    """Where a finding came from."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    origin: DetectionOrigin
    scan_id: ScanIdField
    candidate_ids: tuple[CandidateIdField, ...]
    engines: tuple[EngineRef, ...]
    llm_reviews: tuple[LLMReviewRef, ...] = ()
    codekavach_version: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def _check_origin(self) -> Self:
        if self.origin is DetectionOrigin.DETERMINISTIC and (
            not self.engines or not self.candidate_ids
        ):
            raise ValueError("a deterministic finding needs at least one engine and candidate")
        return self


class Finding(VersionedModel):
    """The final, restored and rated result for one weakness."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW
    SCHEMA_VERSION: ClassVar[int] = 1

    id: FindingIdField
    title: str = Field(min_length=1, max_length=200)
    severity: Severity
    cvss4_vector: str | None = None
    cwe: tuple[CweId, ...] = ()
    owasp: tuple[TaxonomyRef, ...] = ()
    compliance: tuple[TaxonomyRef, ...] = ()
    locations: tuple[Location, ...] = Field(min_length=1)
    evidence: tuple[Evidence, ...] = ()
    impact: Impact
    likelihood: Likelihood
    remediation: str = Field(
        default="",
        max_length=8000,
        description="Guidance text only; never a patch that is applied automatically.",
    )
    references: tuple[Reference, ...] = ()
    status: FindingStatus = FindingStatus.OPEN
    provenance: Provenance
    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    correlation_key: str | None = Field(default=None, pattern=CORRELATION_PATTERN)
    confidence: Confidence
    description: str = Field(default="", max_length=8000)
    cvss4_score: float | None = Field(default=None, ge=0.0, le=10.0)
    taxonomy: tuple[TaxonomyRef, ...] = ()
    taint_path: TaintPath | None = None
    kind: CandidateKind = CandidateKind.VULNERABILITY
    language: Language = Language.UNKNOWN
    status_history: tuple[StatusChange, ...] = ()
    created_at: UtcDatetime
    first_seen_scan_id: ScanIdField | None = None

    @field_validator("title")
    @classmethod
    def _single_line_title(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("title must be a single line")
        return value

    @field_validator("cvss4_vector")
    @classmethod
    def _check_vector(cls, value: str | None) -> str | None:
        if value is not None and not _CVSS4.match(value):
            raise ValueError("cvss4_vector must be a CVSS:4.0 vector string")
        return value

    @field_validator("cvss4_score")
    @classmethod
    def _one_decimal(cls, value: float | None) -> float | None:
        if value is not None and round(value, 1) != value:
            raise ValueError("cvss4_score must have at most one decimal place")
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if (self.cvss4_vector is None) != (self.cvss4_score is None):
            raise ValueError("cvss4_vector and cvss4_score must both be set or both be None")
        if self.status_history:
            if self.status_history[-1].to_status is not self.status:
                raise ValueError("the last status change must end in the current status")
            for earlier, later in zip(self.status_history, self.status_history[1:], strict=False):
                if later.from_status is not earlier.to_status:
                    raise ValueError("status history entries must chain")
        paths = {location.path for location in self.locations}
        if self.taint_path is not None:
            paths.update(self.taint_path.files)
        for item in self.evidence:
            if item.location.path not in paths:
                raise ValueError("evidence must refer to a file among the finding's locations")
        return self

    @property
    def primary_location(self) -> Location:
        """The first location."""
        return self.locations[0]

    @property
    def primary_cwe(self) -> int | None:
        """The first CWE, or None."""
        return self.cwe[0] if self.cwe else None

    def with_status(self, change: StatusChange) -> Self:
        """Return a copy with ``change`` applied; raises InvalidStatusTransition if illegal."""
        status, history = apply_transition(self.status, self.status_history, change)
        return self.evolve(status=status, status_history=history)

    def sort_key(self) -> tuple[int, int, str, int, str]:
        """Severity, then confidence (both descending), then path, line and id."""
        primary = self.primary_location
        return (
            -self.severity.rank,
            -self.confidence.rank,
            primary.path,
            primary.start_line,
            self.id,
        )
