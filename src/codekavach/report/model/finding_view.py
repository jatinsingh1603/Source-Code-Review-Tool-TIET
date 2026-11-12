"""The per-finding audit view: what the detailed-findings section of every format prints.

Owning epic: E30 (E30-02).

``FindingView.from_finding`` turns a ``Finding`` into a flat, renderer-friendly record: a stable
report identifier, both rating axes, the taxonomy and compliance references, evidence with every
secret masked, a data-flow trace table, the model's verdict and description, impact and
remediation text seeded from the local CWE library when the finding carries none. Every renderer
reads views, never raw findings, so the formats cannot drift apart and no format can print an
unmasked secret.

Rating fields that ``Finding`` does not carry yet (CVSS v3.1, EPSS, KEV, ASVS, CAPEC) are read
through ``RatingDetails.from_finding``: an attribute of that name when a later model version adds
one, otherwise a taxonomy reference of the matching scheme. A field that is absent renders as
"not scored", never as an invented value.
"""

from collections.abc import Iterable
from typing import Any, ClassVar, Literal

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import Severity
from codekavach.core.models.finding import Finding
from codekavach.core.models.taxonomy import TaxonomyRef
from codekavach.report.model.library import OWASP_2021, CweEntry, cwe_name, cwe_url, lookup
from codekavach.report.model.masking import mask_lines, mask_text

RiskBand = Literal["critical", "high", "medium", "low", "info"]

_CVSS31_SCHEMES = frozenset({"cvss31", "cvss3.1", "cvss-3.1", "cvss3", "cvss-v3.1"})
_CVSS4_SCHEMES = frozenset({"cvss4", "cvss40", "cvss4.0", "cvss-4.0", "cvss-v4"})
_ASVS_SCHEMES = frozenset({"owasp-asvs", "asvs"})
_CAPEC_SCHEMES = frozenset({"capec"})
_FRAMEWORK_NAMES = {
    "pci-dss": "PCI DSS",
    "iso27001": "ISO/IEC 27001",
    "iso-27001": "ISO/IEC 27001",
    "nist-ssdf": "NIST SSDF",
    "nist-800-53": "NIST SP 800-53",
    "owasp-asvs": "OWASP ASVS",
    "cwe-top25": "CWE Top 25",
    "rbi": "RBI",
    "sebi": "SEBI CSCRF",
    "cert-in": "CERT-In",
    "dpdp": "DPDP Act 2023",
    "gdpr": "GDPR",
    "hipaa": "HIPAA",
    "soc2": "SOC 2",
}
SEVERITY_COLOURS = {
    "critical": "#7a1fa2",
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#f9a825",
    "info": "#1565c0",
}
_LANE = {
    "critical": ("P1", "Immediate", "within 7 days"),
    "high": ("P2", "Short term", "within 30 days"),
    "medium": ("P3", "Medium term", "within 90 days"),
    "low": ("P4", "Planned", "next release cycle"),
    "info": ("P5", "Opportunistic", "as part of routine hardening"),
}
# Top 25 Most Dangerous Software Weaknesses (2024 list) as published by MITRE.
CWE_TOP25_2024 = frozenset(
    {79, 787, 89, 352, 22, 125, 78, 416, 862, 434, 94, 20, 77, 287, 269, 502, 200, 863, 918, 119,
     476, 798, 190, 400, 306}
)  # fmt: skip


def risk_band(score: int) -> RiskBand:
    """The band of a likelihood times impact product on the five-by-five matrix."""
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    if score >= 3:
        return "low"
    return "info"


def _first(refs: Iterable[TaxonomyRef], schemes: frozenset[str]) -> TaxonomyRef | None:
    for ref in refs:
        if ref.scheme in schemes:
            return ref
    return None


def _score(value: Any) -> float | None:
    try:
        return None if value is None else round(float(value), 1)
    except (TypeError, ValueError):
        return None


class RatingDetails(KavachModel):
    """Rating fields read from the finding or its taxonomy references, all optional."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    cvss4_vector: str | None = None
    cvss4_score: float | None = None
    cvss31_vector: str | None = None
    cvss31_score: float | None = None
    epss: float | None = None
    kev: bool | None = None

    @classmethod
    def from_finding(cls, finding: Finding) -> "RatingDetails":
        """The rating fields of ``finding`` that the report prints."""
        refs = (*finding.taxonomy, *finding.compliance)
        v4 = finding.cvss4_vector
        s4 = finding.cvss4_score
        if v4 is None and (ref := _first(refs, _CVSS4_SCHEMES)) is not None:
            v4, s4 = ref.id if ref.id.startswith("CVSS:") else ref.title, _score(ref.title)
        v31 = getattr(finding, "cvss31_vector", None)
        s31 = _score(getattr(finding, "cvss31_score", None))
        if v31 is None and (ref := _first(refs, _CVSS31_SCHEMES)) is not None:
            v31 = ref.id if ref.id.startswith("CVSS:") else ref.title
            s31 = _score(ref.title) if ref.id.startswith("CVSS:") else _score(ref.id)
        return cls(
            cvss4_vector=v4,
            cvss4_score=s4,
            cvss31_vector=v31,
            cvss31_score=s31,
            epss=_score(getattr(finding, "epss", None)),
            kev=getattr(finding, "kev", None),
        )


class ComplianceItem(KavachModel):
    """One clause a finding is evidence against."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    framework: str
    clause: str
    title: str | None = None
    derived: bool = False


class EvidenceLine(KavachModel):
    """One numbered, masked line of a snippet."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    number: int
    text: str
    marked: bool = False


class EvidenceView(KavachModel):
    """A snippet with secrets masked, ready for any renderer."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    path: str
    language: str
    start_line: int
    end_line: int
    role: str = "primary"
    caption: str | None = None
    lines: tuple[EvidenceLine, ...] = ()
    masked_values: int = 0
    masked_at_source: bool = False
    clipped: bool = False

    @property
    def text(self) -> str:
        """The snippet as plain text without line numbers."""
        return "\n".join(line.text for line in self.lines)


class FlowStep(KavachModel):
    """One row of the data-flow trace table."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    index: int
    role: str
    path: str
    line: int
    symbol: str | None = None
    note: str | None = None


class VerdictView(KavachModel):
    """The model's review of the finding, restored to real names."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    provider: str
    model: str
    task: str
    level: str
    is_vulnerable: bool | None
    confidence: str
    reasoning: str = ""
    ledger_seq: int | None = None

    @property
    def label(self) -> str:
        """``Confirmed vulnerable``, ``Not vulnerable`` or ``Undecided``."""
        if self.is_vulnerable is True:
            return "Confirmed vulnerable"
        if self.is_vulnerable is False:
            return "Assessed not vulnerable"
        return "Undecided"


class AuditView(KavachModel):
    """The IIA-style condition, criteria, cause, consequence and corrective action."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    criteria: str
    condition: str
    cause: str
    consequence: str
    corrective_action: str


class FindingView(KavachModel):
    """Everything the detailed-findings section prints about one finding."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    report_id: str
    finding_id: str
    fingerprint: str
    title: str
    severity: str
    severity_rank: int
    confidence: str
    status: str
    kind: str = "vulnerability"
    language: str = "unknown"
    cwe: tuple[int, ...] = ()
    cwe_names: tuple[str, ...] = ()
    cwe_top25: bool = False
    owasp: tuple[ComplianceItem, ...] = ()
    asvs: tuple[str, ...] = ()
    capec: tuple[str, ...] = ()
    compliance: tuple[ComplianceItem, ...] = ()
    rating: RatingDetails = Field(default_factory=RatingDetails)
    likelihood: int = 3
    likelihood_rationale: str = ""
    impact_level: int = 3
    risk_score: int = 9
    risk_band: RiskBand = "medium"
    locations: tuple[str, ...] = ()
    primary_path: str = ""
    primary_line: int = 1
    symbol: str | None = None
    evidence: tuple[EvidenceView, ...] = ()
    flow: tuple[FlowStep, ...] = ()
    verdict: VerdictView | None = None
    description: str
    impact: str
    remediation_short_term: str
    remediation_long_term: str
    remediation_effort: str = "medium"
    priority: str = "P3"
    lane: str = "Medium term"
    lane_window: str = "within 90 days"
    references: tuple[tuple[str, str | None], ...] = ()
    engine: str = ""
    rule_id: str = ""
    detected_by: tuple[str, ...] = ()
    origin: str = "deterministic"
    audit: AuditView | None = None
    first_seen_scan_id: str | None = None

    @property
    def colour(self) -> str:
        """The severity colour used by every format."""
        return SEVERITY_COLOURS.get(self.severity, "#455a64")

    @property
    def cwe_label(self) -> str:
        """``CWE-89 SQL Injection`` or ``n/a``."""
        if not self.cwe:
            return "n/a"
        return ", ".join(f"CWE-{c}" for c in self.cwe)

    @property
    def owasp_label(self) -> str:
        """``A03:2021 Injection`` or ``n/a``."""
        return ", ".join(f"{o.clause} {o.title or ''}".strip() for o in self.owasp) or "n/a"

    @property
    def location_label(self) -> str:
        """``path:line``."""
        return f"{self.primary_path}:{self.primary_line}"

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        *,
        report_id: str,
        context_lines: int | None = None,
    ) -> "FindingView":
        """The view of ``finding``."""
        entry = lookup(tuple(finding.cwe))
        rating = RatingDetails.from_finding(finding)
        owasp = _owasp(finding, entry)
        asvs = _scheme_ids(finding, _ASVS_SCHEMES) or entry.asvs
        capec = _scheme_ids(finding, _CAPEC_SCHEMES) or entry.capec
        compliance = _compliance(finding, entry, asvs)
        likelihood = finding.likelihood.level
        impact_level = finding.impact.level
        score = likelihood * impact_level
        primary = finding.primary_location
        engine = finding.provenance.engines[0] if finding.provenance.engines else None
        severity = finding.severity.value
        priority, lane, window = _LANE.get(severity, _LANE["medium"])
        verdict = _verdict(finding)
        description = mask_text(finding.description.strip()) or entry.description
        if description.strip() == finding.title.strip():
            description = f"{finding.title.rstrip('.')}. {entry.description}"
        impact = mask_text(finding.impact.narrative.strip()) or entry.impact
        short, long_ = _remediation(finding, entry)
        evidence = tuple(_evidence(item, context_lines) for item in finding.evidence)
        flow = _flow(finding)
        title = mask_text(finding.title)
        return cls(
            report_id=report_id,
            finding_id=str(finding.id),
            fingerprint=finding.fingerprint,
            title=title,
            severity=severity,
            severity_rank=finding.severity.rank,
            confidence=finding.confidence.value,
            status=finding.status.value,
            kind=finding.kind.value,
            language=finding.language.value,
            cwe=tuple(finding.cwe),
            cwe_names=tuple(cwe_name(c) for c in finding.cwe),
            cwe_top25=any(c in CWE_TOP25_2024 for c in finding.cwe),
            owasp=owasp,
            asvs=tuple(asvs),
            capec=tuple(capec),
            compliance=compliance,
            rating=rating,
            likelihood=likelihood,
            likelihood_rationale=mask_text(finding.likelihood.rationale),
            impact_level=impact_level,
            risk_score=score,
            risk_band=risk_band(score),
            locations=tuple(
                f"{loc.path}:{loc.start_line}"
                + (f"-{loc.end_line}" if loc.end_line != loc.start_line else "")
                for loc in finding.locations
            ),
            primary_path=primary.path,
            primary_line=primary.start_line,
            symbol=primary.symbol,
            evidence=evidence,
            flow=flow,
            verdict=verdict,
            description=description,
            impact=impact,
            remediation_short_term=short,
            remediation_long_term=long_,
            remediation_effort=entry.effort,
            priority=priority,
            lane=lane,
            lane_window=window,
            references=_references(finding, entry),
            engine=engine.engine if engine else "",
            rule_id=engine.rule_id if engine else "",
            detected_by=tuple(
                sorted({f"{e.engine}:{e.rule_id}" for e in finding.provenance.engines})
            ),
            origin=finding.provenance.origin.value,
            audit=AuditView(
                criteria=_criteria(owasp, asvs, finding),
                condition=f"{title} ({primary.path}:{primary.start_line})",
                cause=entry.description,
                consequence=impact,
                corrective_action=short,
            ),
            first_seen_scan_id=(
                str(finding.first_seen_scan_id) if finding.first_seen_scan_id else None
            ),
        )


def _scheme_ids(finding: Finding, schemes: frozenset[str]) -> tuple[str, ...]:
    refs = (*finding.taxonomy, *finding.compliance)
    return tuple(dict.fromkeys(ref.id for ref in refs if ref.scheme in schemes))


def _owasp(finding: Finding, entry: CweEntry) -> tuple[ComplianceItem, ...]:
    if finding.owasp:
        return tuple(
            ComplianceItem(
                framework="OWASP Top 10",
                clause=ref.id,
                title=ref.title or OWASP_2021.get(ref.id),
            )
            for ref in finding.owasp
        )
    if entry.owasp:
        return (
            ComplianceItem(
                framework="OWASP Top 10",
                clause=entry.owasp,
                title=OWASP_2021.get(entry.owasp),
                derived=True,
            ),
        )
    return ()


def _compliance(
    finding: Finding, entry: CweEntry, asvs: tuple[str, ...]
) -> tuple[ComplianceItem, ...]:
    skip = _CVSS31_SCHEMES | _CVSS4_SCHEMES | _CAPEC_SCHEMES | {"owasp-top10"}
    stated = [
        ComplianceItem(
            framework=_FRAMEWORK_NAMES.get(ref.scheme, ref.scheme.upper()),
            clause=ref.id,
            title=ref.title,
        )
        for ref in finding.compliance
        if ref.scheme not in skip
    ]
    if stated:
        return tuple(stated)
    # Derived mapping: the clauses a secure-code finding of this class is evidence against.
    derived: list[ComplianceItem] = []
    if asvs:
        derived.append(
            ComplianceItem(
                framework="OWASP ASVS 4.0.3",
                clause=asvs[0],
                title="Verification requirement",
                derived=True,
            )
        )
    derived.extend(
        (
            ComplianceItem(
                framework="PCI DSS 4.0",
                clause="6.2.4",
                title="Software engineering techniques prevent common attacks",
                derived=True,
            ),
            ComplianceItem(
                framework="ISO/IEC 27001:2022",
                clause="A.8.28",
                title="Secure coding",
                derived=True,
            ),
            ComplianceItem(
                framework="NIST SSDF",
                clause="PW.7.2",
                title="Review and analyse code for vulnerabilities",
                derived=True,
            ),
        )
    )
    if any(c in CWE_TOP25_2024 for c in finding.cwe):
        derived.append(
            ComplianceItem(
                framework="CWE Top 25 (2024)",
                clause=", ".join(f"CWE-{c}" for c in finding.cwe if c in CWE_TOP25_2024),
                title="Most dangerous software weaknesses",
                derived=True,
            )
        )
    _ = entry
    return tuple(derived)


def _remediation(finding: Finding, entry: CweEntry) -> tuple[str, str]:
    own = mask_text(finding.remediation.strip())
    if own:
        return own, entry.long_term
    return entry.short_term, entry.long_term


def _references(finding: Finding, entry: CweEntry) -> tuple[tuple[str, str | None], ...]:
    refs: dict[str, str | None] = {ref.title: ref.url for ref in finding.references}
    for cwe in finding.cwe:
        refs.setdefault(f"MITRE CWE-{cwe}: {cwe_name(cwe)}", cwe_url(cwe))
    if entry.cheat_sheet:
        refs.setdefault("OWASP Cheat Sheet Series", entry.cheat_sheet)
    for ref in finding.owasp:
        if ref.id.endswith(":2021"):
            slug = ref.id.split(":")[0]
            title = (ref.title or OWASP_2021.get(ref.id, "")).replace(" ", "_")
            refs.setdefault(
                f"OWASP Top 10 {ref.id} {ref.title or ''}".strip(),
                f"https://owasp.org/Top10/{slug}_2021-{title}/",
            )
    return tuple(refs.items())


def _verdict(finding: Finding) -> VerdictView | None:
    reviews = finding.provenance.llm_reviews
    if not reviews:
        return None
    review = reviews[-1]
    return VerdictView(
        provider=review.provider,
        model=review.model,
        task=review.task,
        level=review.level.value,
        is_vulnerable=review.is_vulnerable,
        confidence=review.confidence.value,
        reasoning=mask_text(review.reasoning),
        ledger_seq=review.ledger_seq,
    )


def _evidence(item: Any, context_lines: int | None) -> EvidenceView:
    location = item.location
    lines = list(item.lines)
    if context_lines is not None:
        first = location.start_line - context_lines
        last = location.end_line + context_lines
        kept = [line for line in lines if first <= line.number <= last]
        lines = kept or lines
    raw = [line.text.expose() for line in lines]
    masked, count = mask_lines(raw, path=location.path, language=item.language.value)
    return EvidenceView(
        path=location.path,
        language=item.language.value,
        start_line=location.start_line,
        end_line=location.end_line,
        role=item.role.value,
        caption=mask_text(item.caption) if item.caption else None,
        lines=tuple(
            EvidenceLine(
                number=line.number,
                text=text,
                marked=location.start_line <= line.number <= location.end_line,
            )
            for line, text in zip(lines, masked, strict=True)
        ),
        masked_values=count,
        masked_at_source=item.masked,
        clipped=item.clipped,
    )


def _flow(finding: Finding) -> tuple[FlowStep, ...]:
    if finding.taint_path is None:
        return ()
    return tuple(
        FlowStep(
            index=index,
            role=step.role.value,
            path=step.location.path,
            line=step.location.start_line,
            symbol=step.location.symbol,
            note=mask_text(step.note) if step.note else None,
        )
        for index, step in enumerate(finding.taint_path.steps, start=1)
    )


def _criteria(owasp: tuple[ComplianceItem, ...], asvs: tuple[str, ...], finding: Finding) -> str:
    parts = [f"OWASP Top 10 {o.clause} {o.title or ''}".strip() for o in owasp]
    parts.extend(f"OWASP ASVS {item}" for item in asvs[:2])
    parts.extend(f"CWE-{c}" for c in finding.cwe)
    return "; ".join(parts) or "Secure coding practice"


def severity_order() -> tuple[str, ...]:
    """Severity values, most severe first."""
    return tuple(item.value for item in sorted(Severity, key=lambda s: -s.rank))
