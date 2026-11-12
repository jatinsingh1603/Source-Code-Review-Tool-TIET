"""Methodology, tools and the risk rating method.

Owning epic: E30 (E30-01). The phases follow NIST SP 800-115 and the OWASP Code Review Guide.
"""

from enum import StrEnum
from typing import ClassVar

from codekavach.core.models.base import DataClassification, KavachModel


class MethodPhase(StrEnum):
    """The review phases, in order."""

    planning = "planning"
    discovery = "discovery"
    analysis = "analysis"
    privacy = "privacy"
    validation = "validation"
    rating = "rating"
    reporting = "reporting"


class ToolRecord(KavachModel):
    """One tool or engine used in the review."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    name: str
    version: str
    role: str
    licence: str = ""
    distribution_mode: str = "local"
    configuration_digest: str | None = None


class MethodStep(KavachModel):
    """One step of the method."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    phase: MethodPhase
    title: str
    description: str
    automated: bool = True
    sources: tuple[str, ...] = ()


class PrivacyLevelRow(KavachModel):
    """One privacy level and what it sends."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    level: str
    name: str
    sends: str


class Methodology(KavachModel):
    """How the review was performed."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    steps: tuple[MethodStep, ...] = ()
    tools: tuple[ToolRecord, ...] = ()
    rule_packs: tuple[str, ...] = ()
    privacy_levels: tuple[PrivacyLevelRow, ...] = ()
    engines_unavailable: tuple[str, ...] = ()
    techniques_not_performed: tuple[str, ...] = ()


class RatingMethod(KavachModel):
    """How severity and risk were rated."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    severity_scale: tuple[tuple[str, str, str], ...] = ()
    likelihood_scale: tuple[tuple[int, str], ...] = ()
    impact_scale: tuple[tuple[int, str], ...] = ()
    cvss_nomenclature: str = ""
    cwe_mapping_rule: str = ""
    confidence_rule: str = ""


def default_steps() -> tuple[MethodStep, ...]:
    """The CodeKavach pipeline as audit-method steps."""
    return (
        MethodStep(
            phase=MethodPhase.planning,
            title="Scoping and policy",
            description="Scope, exclusions and the per-path privacy policy were fixed in the "
            "project configuration before the run; the configuration digest is recorded.",
            sources=("NIST SP 800-115 3.1", "OWASP Code Review Guide 2.0"),
        ),
        MethodStep(
            phase=MethodPhase.discovery,
            title="Code crawl",
            description="Files were discovered, their languages detected and parsed with "
            "Tree-sitter into syntax trees, symbols and call graphs.",
        ),
        MethodStep(
            phase=MethodPhase.analysis,
            title="Deterministic analysis",
            description="Structural security rules, intra- and inter-procedural taint analysis "
            "from sources to sinks, and the configured external engines produced candidates; "
            "duplicates were merged by fingerprint.",
        ),
        MethodStep(
            phase=MethodPhase.privacy,
            title="Privacy preparation",
            description="Each candidate was cut to a minimal code slice, secrets and personal "
            "data were redacted and identifiers pseudonymised as the privacy level requires, and "
            "the payload re-scanned by an independent egress guard before any model call.",
        ),
        MethodStep(
            phase=MethodPhase.validation,
            title="Model-assisted triage",
            description="Sanitised payloads were reviewed by the configured language model with "
            "structured output; every request is recorded in a hash-chained egress ledger. The "
            "model's answer is advisory: it can lower confidence but never closes a finding.",
        ),
        MethodStep(
            phase=MethodPhase.rating,
            title="Risk rating",
            description="Findings were rated by severity, CVSS where available, and on a five by "
            "five likelihood and impact matrix, then mapped to CWE, OWASP and compliance clauses.",
        ),
        MethodStep(
            phase=MethodPhase.reporting,
            title="Reporting",
            description="Pseudonyms were restored locally, evidence was cut from the original "
            "files with secrets masked, and every report format was rendered from one document "
            "model with an integrity manifest.",
        ),
    )


def default_privacy_levels() -> tuple[PrivacyLevelRow, ...]:
    """The five privacy levels (docs/ARCHITECTURE.md section 6)."""
    return (
        PrivacyLevelRow(
            level="L0",
            name="Air-gapped",
            sends="Nothing leaves; only local engines or a local model are used.",
        ),
        PrivacyLevelRow(
            level="L1",
            name="Redacted",
            sends="Code with secrets and personal data replaced by typed placeholders.",
        ),
        PrivacyLevelRow(
            level="L2",
            name="Pseudonymised",
            sends="L1 plus identifiers, literals and comments pseudonymised.",
        ),
        PrivacyLevelRow(
            level="L3",
            name="Minimal slice (default)",
            sends="L2 applied to the minimal code slice of each candidate only.",
        ),
        PrivacyLevelRow(
            level="L4",
            name="Facts only",
            sends="No code: abstract data-flow facts and questions.",
        ),
    )


def default_rating_method() -> RatingMethod:
    """The rating method the report explains."""
    return RatingMethod(
        severity_scale=(
            ("critical", "9.0 - 10.0", "Directly exploitable; compromise of the system or data."),
            ("high", "7.0 - 8.9", "Exploitable with little effort; serious impact."),
            ("medium", "4.0 - 6.9", "Exploitable under specific conditions; moderate impact."),
            ("low", "0.1 - 3.9", "Limited impact or hard to exploit; defence in depth."),
            ("info", "0.0", "Observation or hardening opportunity; no direct risk."),
        ),
        likelihood_scale=(
            (1, "Rare: requires unusual conditions or insider access"),
            (2, "Unlikely: requires authentication and specific conditions"),
            (3, "Possible: reachable by an authenticated user"),
            (4, "Likely: reachable from the network with little effort"),
            (5, "Almost certain: reachable anonymously, trivially exploitable"),
        ),
        impact_scale=(
            (1, "Negligible: no data or service affected"),
            (2, "Minor: limited, non-sensitive data or degraded service"),
            (3, "Moderate: some sensitive data or a single customer affected"),
            (4, "Major: sensitive data of many customers or a key function affected"),
            (5, "Severe: full system compromise, regulatory breach or financial loss"),
        ),
        cvss_nomenclature=(
            "CVSS v4.0 base scores are reported as CVSS-B (base metrics only); CVSS v3.1 vectors "
            "are given alongside for tools that do not yet read v4.0. Where a finding has no "
            "vector it is marked 'not scored' and its severity comes from the rule."
        ),
        cwe_mapping_rule=(
            "Each finding is mapped to the most specific CWE weakness the rule or engine reports; "
            "OWASP Top 10 (2021) categories and compliance clauses are derived from the CWE "
            "where the finding does not carry its own mapping, and are marked as derived."
        ),
        confidence_rule=(
            "Confidence reflects the detection technique (taint path or structural match) and "
            "the model's assessment; a model can lower confidence but never dismiss a finding."
        ),
    )
