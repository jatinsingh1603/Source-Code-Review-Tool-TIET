"""The report document: what a renderer receives, and nothing it should not.

Owning epic: E13. MVP; extended by E30, which adds the audit report structure, the narrative
sections and the compliance mappings.

A renderer receives a finished ``ReportDocument`` and never a ``CodeSlice``, a ``SanitisedPayload``
or a vault value. The findings carry evidence cut from the original files (real names, real line
numbers), because the report is for the client on the client's machine; the privacy attestation
carries counts, hashes and settings only.
"""

from datetime import datetime
from typing import ClassVar, Final

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.finding import Finding
from codekavach.core.models.scan import Scan
from codekavach.core.models.summary import ScanSummary

NOT_COVERED: Final = (
    "What this attestation does not cover. The zero-leak check is verbatim: it looks for the "
    "listed terms as written and does not detect a term that was paraphrased, split or encoded. "
    "The structure of the code, its control flow, the libraries it uses and the technology stack "
    "are still disclosed to the model whatever the privacy level. Structural leakage, meaning what "
    "an observer could infer from that structure, is measured separately by the evaluation "
    "harness and is not part of this check."
)
OFFLINE_NOTICE: Final = (
    "This run used the {kind} provider, which answers locally. The ledger therefore shows what "
    "would have left the environment, not what did: no connection to any model was made."
)


class ZeroLeak(KavachModel):
    """The result of searching the ledger payloads for a list of terms that must not appear."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    checked: bool = False
    terms_checked: int = Field(default=0, ge=0)
    occurrences: int = Field(default=0, ge=0)

    @property
    def passed(self) -> bool:
        """True when a check ran and found no occurrence."""
        return self.checked and self.occurrences == 0

    @property
    def text(self) -> str:
        """One line for the attestation."""
        if not self.checked:
            return "not checked in this run"
        verdict = "no occurrence" if self.occurrences == 0 else f"{self.occurrences} occurrence(s)"
        return f"{self.terms_checked} listed terms searched in every ledger payload: {verdict}"


class PrivacyAttestation(KavachModel):
    """What was removed, what was disclosed, what left, and what the check does not cover."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    default_level: str
    levels: tuple[tuple[str, str], ...] = ()
    provider: str | None = None
    model: str | None = None
    provider_is_local: bool = True
    offline_notice: str | None = None
    disclosure: tuple[tuple[str, str], ...] = ()
    ledger_head_hash: str | None = None
    ledger_entries: int = Field(default=0, ge=0)
    entries_by_outcome: tuple[tuple[str, int], ...] = ()
    zero_leak: ZeroLeak = ZeroLeak()
    retention: str = "not set"
    not_covered: str = NOT_COVERED

    def figure(self, name: str, default: str = "n/a") -> str:
        """One disclosure figure by name."""
        return dict(self.disclosure).get(name, default)


class ReportDocument(KavachModel):
    """The minimal report of Demo 1: title, scan, summary, findings and privacy attestation."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    title: str
    classification: str = "Confidential"
    auditor: str | None = None
    generated_at: datetime
    scan: Scan
    summary: ScanSummary
    findings: tuple[Finding, ...] = ()
    not_reviewed: tuple[tuple[str, int], ...] = ()
    privacy_attestation: PrivacyAttestation | None = None
    tools: tuple[tuple[str, str], ...] = ()


class ReportOutput(KavachModel):
    """One file the report stage wrote, as ``report.outputs`` records it."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    format: str
    path: str
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
