"""Severity of a finding under a configurable policy.

Owning epic: E13 (MVP); extended by E29 with the severity policy. The severity is read from the
finding's rating (the CVSS v4.0 score by default, or the OWASP overall rating, or the stricter of
the two) through configurable score bands, then adjusted by the policy's downgrades (test code,
vendored code). Without a rating it falls back to an engine-supplied score, then the engine's own
severity, then a CWE family default.

The model's verdict does not change the severity by default. A "not vulnerable" answer lowers a
finding's confidence (see ``codekavach.risk.stage``) and is recorded, but a plausible rationale is
not proof of a false positive (``docs/research/INSIGHTS.md`` section 2.2 item 3). A deployment may
opt in to ``model_downgrade``, which lowers the severity one step when the model answers "not
vulnerable" with at least ``model_downgrade_min_confidence``; the step is recorded on the finding.

The policy is read from the YAML file named by ``$CODEKAVACH_RISK_POLICY`` when set; otherwise
the defaults below (FIRST qualitative bands) apply.
"""

import math
import os
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, Literal

import yaml
from pydantic import Field, ValidationError, model_validator

from codekavach.core.log import get_logger
from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.enums import Confidence, Severity
from codekavach.core.models.verdict import LLMVerdict

if TYPE_CHECKING:
    from codekavach.risk.rating import RatingResult

_log = get_logger(__name__)

SCORE_PROPERTY: Final = "cvss4_score"
POLICY_ENV: Final = "CODEKAVACH_RISK_POLICY"

# A small table of CWE families, used only when neither a score nor an engine severity exists.
_CWE_DEFAULTS: Final[dict[int, Severity]] = {
    **dict.fromkeys((77, 78, 89, 94, 95, 502, 611, 918), Severity.HIGH),  # injection, deserialise
    **dict.fromkeys((259, 321, 798), Severity.HIGH),  # hard-coded credentials and keys
    **dict.fromkeys((22, 79, 287, 306, 352, 434, 639, 862, 863), Severity.MEDIUM),
    **dict.fromkeys((326, 327, 328, 330, 338), Severity.MEDIUM),  # weak cryptography
    **dict.fromkeys((200, 209, 532, 778), Severity.LOW),  # information exposure, logging
}
FALLBACK: Final = Severity.MEDIUM
_ORDER: Final = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
_OWASP_TO_SEVERITY: Final = {
    "note": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class SeverityBand(KavachModel):
    """Scores from ``min_score`` up to the next band's minimum map to ``severity``."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    severity: Severity
    min_score: float = Field(ge=0.0, le=10.0)


DEFAULT_BANDS: Final = (
    SeverityBand(severity=Severity.CRITICAL, min_score=9.0),
    SeverityBand(severity=Severity.HIGH, min_score=7.0),
    SeverityBand(severity=Severity.MEDIUM, min_score=4.0),
    SeverityBand(severity=Severity.LOW, min_score=0.1),
    SeverityBand(severity=Severity.INFO, min_score=0.0),
)


class SeverityPolicy(KavachModel):
    """How a rating becomes a severity."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    source: Literal["cvss4", "owasp", "strictest"] = "cvss4"
    bands: tuple[SeverityBand, ...] = DEFAULT_BANDS
    downgrade_test_code: bool = True
    downgrade_vendored: bool = True
    engine_floor: bool = Field(
        default=False,
        description="Never rate below the severity the reporting engine assigned.",
    )
    engine_authoritative_kinds: tuple[str, ...] = Field(
        default=("dependency", "misconfiguration"),
        description="Candidate kinds whose engine rates each instance; its severity is used.",
    )
    model_downgrade: bool = Field(
        default=False,
        description="Lower one step when the model says 'not vulnerable' confidently enough.",
    )
    model_downgrade_min_confidence: Confidence = Confidence.HIGH

    @model_validator(mode="after")
    def _check_bands(self) -> "SeverityPolicy":
        if not self.bands or min(band.min_score for band in self.bands) != 0.0:
            raise ValueError("severity bands must include one starting at 0.0")
        return self

    def from_score(self, score: float) -> Severity:
        """The severity of a CVSS score under the policy's bands."""
        for band in sorted(self.bands, key=lambda item: item.min_score, reverse=True):
            if score >= band.min_score:
                return band.severity
        return Severity.INFO


DEFAULT_POLICY: Final = SeverityPolicy()


def load_policy(path: Path | None = None) -> SeverityPolicy:
    """The policy in ``path`` or ``$CODEKAVACH_RISK_POLICY``, else the default policy."""
    target = path or (Path(os.environ[POLICY_ENV]) if os.environ.get(POLICY_ENV) else None)
    if target is None:
        return DEFAULT_POLICY
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        return SeverityPolicy.model_validate(raw.get("severity", raw))
    except (OSError, yaml.YAMLError, ValidationError, AttributeError) as error:
        _log.warning("risk_policy_invalid", path=str(target), reason=type(error).__name__)
        return DEFAULT_POLICY


def step_down(severity: Severity, steps: int = 1) -> Severity:
    """``severity`` lowered by ``steps`` (never below info)."""
    return _ORDER[max(0, _ORDER.index(severity) - steps)]


def _score_of(candidate: Candidate) -> float | None:
    for key, value in candidate.properties:
        if key == SCORE_PROPERTY:
            try:
                score = float(value)
            except ValueError:
                return None
            return score if math.isfinite(score) and 0.0 <= score <= 10.0 else None
    return None


def severity_from_rating(
    rating: "RatingResult", policy: SeverityPolicy
) -> tuple[Severity, tuple[str, ...]]:
    """The severity a rating gives under ``policy`` and the policy steps applied."""
    by_cvss = policy.from_score(rating.cvss4_score)
    by_owasp = _OWASP_TO_SEVERITY[rating.owasp.overall]
    if policy.source == "cvss4":
        severity = by_cvss
    elif policy.source == "owasp":
        severity = by_owasp
    else:
        severity = max(by_cvss, by_owasp, key=_ORDER.index)
    steps: list[str] = []
    context = rating.context
    if (
        context.engine_severity is not None
        and context.kind.value in policy.engine_authoritative_kinds
    ):
        severity = context.engine_severity
        steps.append("policy:engine_severity")
    if policy.downgrade_test_code and context.is_test_code:
        severity = step_down(severity)
        steps.append("policy:test_code_downgrade")
    elif policy.downgrade_vendored and context.is_vendored:
        severity = step_down(severity)
        steps.append("policy:vendored_downgrade")
    if policy.engine_floor and context.engine_severity is not None:
        floor = context.engine_severity
        if _ORDER.index(floor) > _ORDER.index(severity):
            severity = floor
            steps.append("policy:engine_floor")
    return severity, tuple(steps)


def map_severity(
    candidate: Candidate,
    verdict: LLMVerdict | None,
    *,
    rating: "RatingResult | None" = None,
    policy: SeverityPolicy = DEFAULT_POLICY,
) -> Severity:
    """The severity of ``candidate``: from its rating when given, else score, engine or CWE.

    ``verdict`` only matters when ``policy.model_downgrade`` is set (off by default).
    """
    if rating is not None:
        severity, _ = severity_from_rating(rating, policy)
    else:
        score = _score_of(candidate)
        if score is not None:
            severity = policy.from_score(score)
        elif candidate.engine_severity is not None:
            severity = candidate.engine_severity
        else:
            severity = next(
                (_CWE_DEFAULTS[c] for c in candidate.cwe if c in _CWE_DEFAULTS), FALLBACK
            )
    if verdict is not None:
        severity, _ = apply_model_downgrade(
            severity, verdict.is_vulnerable, verdict.confidence, policy
        )
    return severity


def apply_model_downgrade(
    severity: Severity,
    is_vulnerable: bool | None,
    confidence: Confidence | None,
    policy: SeverityPolicy,
) -> tuple[Severity, bool]:
    """Lower ``severity`` one step when the policy opts in and the model confidently dismisses."""
    if (
        policy.model_downgrade
        and is_vulnerable is False
        and confidence is not None
        and confidence.rank >= policy.model_downgrade_min_confidence.rank
    ):
        return step_down(severity), True
    return severity, False
