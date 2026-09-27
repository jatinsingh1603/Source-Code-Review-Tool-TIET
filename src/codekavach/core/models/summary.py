"""Deterministic scan aggregates: ScanSummary and the ledger-derived EgressTotals.

Owning epic: E02.

Every consumer (report, CLI table, dashboard, privacy attestation) reads the same numbers from
here, so they cannot disagree. ``EgressTotals`` is derived from ledger entries only, never from
counters kept elsewhere, because a second bookkeeping path could disagree with the ledger and
make the attestation wrong. Both builders sort explicitly and give identical results for every
permutation of their input. The summary holds counts only: no paths, names or code.
"""

import math
from collections import Counter
from collections.abc import Iterable
from typing import ClassVar, Self

from pydantic import Field, model_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.enums import (
    EgressOutcome,
    FindingStatus,
    Language,
    PrivacyLevel,
    Severity,
)
from codekavach.core.models.finding import Finding

TOP_CWE_LIMIT = 10
SEVERITY_ORDER: tuple[Severity, ...] = tuple(sorted(Severity, reverse=True))
STATUS_ORDER: tuple[FindingStatus, ...] = tuple(FindingStatus)
LEVEL_ORDER: tuple[PrivacyLevel, ...] = tuple(sorted(PrivacyLevel))


class EgressTotals(KavachModel):
    """Totals over the egress ledger entries of one scan."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    requests_sent: int = Field(ge=0)
    requests_blocked: int = Field(ge=0)
    requests_failed: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    tokens_estimated: bool
    levels: tuple[tuple[PrivacyLevel, int], ...]

    @model_validator(mode="after")
    def _check_levels(self) -> Self:
        if tuple(level for level, _ in self.levels) != LEVEL_ORDER:
            raise ValueError("levels must list all five privacy levels in strictness order")
        if any(count < 0 for _, count in self.levels):
            raise ValueError("level counts must not be negative")
        if sum(count for _, count in self.levels) != self.requests_sent:
            raise ValueError("level counts must add up to requests_sent")
        return self

    @classmethod
    def empty(cls) -> Self:
        """Totals for a scan that sent nothing."""
        return cls(
            requests_sent=0,
            requests_blocked=0,
            requests_failed=0,
            prompt_tokens=0,
            completion_tokens=0,
            tokens_estimated=False,
            levels=tuple((level, 0) for level in LEVEL_ORDER),
        )

    @classmethod
    def from_records(cls, records: Iterable[EgressRecord]) -> Self:
        """Aggregate ledger entries; the chain must already have been verified (E12)."""
        entries = sorted(records, key=lambda record: record.seq)
        completed = {
            record.ref_seq: record
            for record in entries
            if record.outcome is EgressOutcome.COMPLETED and record.ref_seq is not None
        }
        outcomes = Counter(record.outcome for record in entries)
        prompt_tokens = 0
        completion_tokens = 0
        estimated = False
        levels: Counter[PrivacyLevel] = Counter()
        for record in entries:
            if record.outcome is EgressOutcome.SENT:
                levels[record.level] += 1
                counts = completed.get(record.seq, record).token_counts
                prompt_tokens += counts.prompt
                estimated = estimated or counts.estimated
            elif record.outcome is EgressOutcome.COMPLETED:
                completion_tokens += record.token_counts.completion or 0
                if record.token_counts.completion is not None:
                    estimated = estimated or record.token_counts.estimated
        return cls(
            requests_sent=outcomes[EgressOutcome.SENT],
            requests_blocked=outcomes[EgressOutcome.BLOCKED],
            requests_failed=outcomes[EgressOutcome.FAILED],
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            tokens_estimated=estimated,
            levels=tuple((level, levels[level]) for level in LEVEL_ORDER),
        )


class ScanSummary(KavachModel):
    """The single aggregate of one scan's findings, scope and egress."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    findings_total: int = Field(ge=0)
    by_severity: tuple[tuple[Severity, int], ...]
    by_status: tuple[tuple[FindingStatus, int], ...]
    by_language: tuple[tuple[Language, int], ...] = ()
    top_cwes: tuple[tuple[int, int], ...] = Field(default=(), max_length=TOP_CWE_LIMIT)
    risk_matrix: tuple[tuple[int, int, int], ...] = ()
    files_scanned: int = Field(ge=0)
    lines_scanned: int = Field(ge=0)
    candidates_total: int = Field(ge=0)
    candidates_reviewed_by_llm: int = Field(ge=0)
    egress: EgressTotals
    duration_seconds: float = Field(ge=0.0, allow_inf_nan=False)

    @model_validator(mode="after")
    def _check_totals(self) -> Self:
        if tuple(severity for severity, _ in self.by_severity) != SEVERITY_ORDER:
            raise ValueError("by_severity must list all five severities, critical first")
        if tuple(status for status, _ in self.by_status) != STATUS_ORDER:
            raise ValueError("by_status must list all six statuses in declaration order")
        cells = [(likelihood, impact) for likelihood, impact, _ in self.risk_matrix]
        if any(not (1 <= a <= 5 and 1 <= b <= 5) for a, b in cells):
            raise ValueError("risk matrix levels must be between 1 and 5")
        if len(set(cells)) != len(cells):
            raise ValueError("a risk matrix cell must not be repeated")
        sums = (
            sum(count for _, count in self.by_severity),
            sum(count for _, count in self.by_status),
            sum(count for _, _, count in self.risk_matrix),
        )
        if any(total != self.findings_total for total in sums):
            raise ValueError("findings_total must equal the severity, status and matrix sums")
        if self.candidates_reviewed_by_llm > self.candidates_total:
            raise ValueError("more candidates reviewed by an LLM than candidates in total")
        if not math.isfinite(self.duration_seconds):
            raise ValueError("duration_seconds must be finite")
        return self

    @classmethod
    def from_findings(
        cls,
        findings: Iterable[Finding],
        *,
        files_scanned: int,
        lines_scanned: int,
        candidates_total: int,
        candidates_reviewed_by_llm: int,
        egress: EgressTotals,
        duration_seconds: float,
    ) -> Self:
        """Aggregate findings; the result does not depend on the order of ``findings``."""
        items = list(findings)
        severities = Counter(finding.severity for finding in items)
        statuses = Counter(finding.status for finding in items)
        languages = Counter(finding.language for finding in items)
        cwes = Counter(f.primary_cwe for f in items if f.primary_cwe is not None)
        matrix = Counter((f.likelihood.level, f.impact.level) for f in items)
        return cls(
            findings_total=len(items),
            by_severity=tuple((severity, severities[severity]) for severity in SEVERITY_ORDER),
            by_status=tuple((status, statuses[status]) for status in STATUS_ORDER),
            by_language=tuple(
                sorted(languages.items(), key=lambda pair: (-pair[1], pair[0].value))
            ),
            top_cwes=tuple(sorted(cwes.items(), key=lambda pair: (-pair[1], pair[0])))[
                :TOP_CWE_LIMIT
            ],
            risk_matrix=tuple((a, b, count) for (a, b), count in sorted(matrix.items())),
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            candidates_total=candidates_total,
            candidates_reviewed_by_llm=candidates_reviewed_by_llm,
            egress=egress,
            duration_seconds=duration_seconds,
        )

    def count(self, severity: Severity) -> int:
        """Number of findings with ``severity``."""
        return dict(self.by_severity)[severity]

    @property
    def highest_severity(self) -> Severity | None:
        """The most severe level with at least one finding, or None."""
        return next((severity for severity, count in self.by_severity if count), None)
