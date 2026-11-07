"""Models of the restore stage: the raw verdict record and the restored verdict.

Owning epic: E10 (issue E10-02).

``CandidateVerdict`` is the record ``verdicts.raw`` carries: one model answer, in pseudonym space,
bound to its candidate. ``RestoredVerdict`` is the answer after de-pseudonymisation. Its text holds
original names, so it is client data (RAW). It is the one place where originals legitimately
reappear (ARCHITECTURE section 6.2 step 9), and it is never logged: its ``repr`` shows counts only.
Everything that is not text (counts, drop reasons, enums) is metadata.
"""

from typing import ClassVar, Literal

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import Confidence, ContextKind
from codekavach.core.models.ids import CandidateIdField
from codekavach.core.models.location import Location
from codekavach.core.models.taxonomy import CweId
from codekavach.core.models.verdict import LLMVerdict

DroppedSection = Literal["reasoning", "impact", "remediation", "needs_context", "cited_lines"]
DropReason = Literal["unknown_pseudonym", "unmappable_line"]


class CandidateVerdict(KavachModel):
    """One model answer for one candidate, as ``verdicts.raw`` carries it (pseudonym space)."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.UNTRUSTED

    candidate_id: CandidateIdField
    verdict: LLMVerdict

    def __repr__(self) -> str:
        return f"CandidateVerdict({self.candidate_id})"

    __str__ = __repr__


class DroppedClaim(KavachModel):
    """One unit of a verdict that could not be anchored, and the rule that dropped it."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    section: DroppedSection
    reason: DropReason


class RestoreStats(KavachModel):
    """Counts of what restoration did; no text, so it can reach a report."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    pseudonyms: int = 0
    secret_placeholders: int = 0
    pii_placeholders: int = 0
    term_placeholders: int = 0
    unknown_pseudonyms: int = 0
    unmappable_lines: int = 0


class RestoredContext(KavachModel):
    """A request for more code, with its symbol restored to the real name."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    kind: ContextKind
    symbol: str
    reason: str

    def __repr__(self) -> str:
        return f"RestoredContext({self.kind.value})"

    __str__ = __repr__


class RestoredVerdict(KavachModel):
    """A verdict after restoration: original names, real file lines, and what was dropped.

    When ``verdict_dropped`` is true the model's primary assertion could not be anchored, so the
    text fields are empty and the candidate keeps only its deterministic evidence (I4).
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    candidate_id: CandidateIdField
    verdict_dropped: bool
    is_vulnerable: bool | None
    confidence: Confidence
    cwe: tuple[CweId, ...] = ()
    reasoning: str = ""
    impact: str = ""
    remediation: str = ""
    needs_context: tuple[RestoredContext, ...] = ()
    cited_locations: tuple[Location, ...] = ()
    dropped_claims: tuple[DroppedClaim, ...] = ()
    restore_stats: RestoreStats = RestoreStats()

    def __repr__(self) -> str:
        return (
            f"RestoredVerdict({self.candidate_id}, dropped={self.verdict_dropped}, "
            f"claims={len(self.dropped_claims)}, locations={len(self.cited_locations)})"
        )

    __str__ = __repr__
