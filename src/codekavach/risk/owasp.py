"""The OWASP Risk Rating Methodology: likelihood and impact factors, bands and overall severity.

Owning epic: E29. Source: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology. Each
factor is an integer 0 to 9. Likelihood is the mean of the four threat-agent and four
vulnerability factors; technical impact the mean of loss of confidentiality, integrity,
availability and accountability; business impact the mean of financial damage, reputation damage,
non-compliance and privacy violation. A mean below 3 is LOW, below 6 MEDIUM, otherwise HIGH, and
the overall severity is read from the methodology's three-by-three table. As the methodology
advises, business impact replaces technical impact only when the business context is known (an
asset criticality was configured).

``rate_owasp`` pre-fills the threat factors from the weakness family, adjusts opportunity and
population size with the context (authenticated, local), and derives the technical impact
factors from the CVSS v4.0 vector so both ratings describe the same consequences.
"""

from typing import ClassVar, Final, Literal

from pydantic import Field

from codekavach.core.log import get_logger
from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.risk.context import Criticality, RatingContext
from codekavach.risk.cvss.v4 import Cvss4Vector
from codekavach.risk.taxonomy.loader import ThreatFactors

_log = get_logger(__name__)

Band = Literal["low", "medium", "high"]
Overall = Literal["note", "low", "medium", "high", "critical"]
_Factor = Field(ge=0, le=9)

# Overall risk severity, keyed by (impact band, likelihood band).
OVERALL: Final[dict[tuple[Band, Band], Overall]] = {
    ("high", "low"): "medium",
    ("high", "medium"): "high",
    ("high", "high"): "critical",
    ("medium", "low"): "low",
    ("medium", "medium"): "medium",
    ("medium", "high"): "high",
    ("low", "low"): "note",
    ("low", "medium"): "low",
    ("low", "high"): "medium",
}

# Business impact factors (financial, reputation, non-compliance, privacy) per asset criticality.
BUSINESS: Final[dict[Criticality, tuple[int, int, int, int]]] = {
    "low": (1, 1, 2, 3),
    "medium": (3, 4, 5, 5),
    "high": (7, 5, 5, 7),
    "critical": (9, 9, 7, 9),
}
_DEFAULT_THREAT: Final = ThreatFactors(
    skill=5,
    motive=5,
    opportunity=7,
    size=6,
    ease_of_discovery=5,
    ease_of_exploit=5,
    awareness=5,
    intrusion_detection=8,
)


class _Factors(KavachModel):
    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    def mean(self) -> float:
        """The mean of the factors."""
        values = [int(v) for v in self.model_dump().values()]
        return sum(values) / len(values)


class ThreatAgentFactors(_Factors):
    """Who might exploit the weakness."""

    skill_level: int = _Factor
    motive: int = _Factor
    opportunity: int = _Factor
    size: int = _Factor


class VulnerabilityFactors(_Factors):
    """How easy the weakness is to find and exploit."""

    ease_of_discovery: int = _Factor
    ease_of_exploit: int = _Factor
    awareness: int = _Factor
    intrusion_detection: int = _Factor


class TechnicalImpactFactors(_Factors):
    """Technical consequences."""

    loss_of_confidentiality: int = _Factor
    loss_of_integrity: int = _Factor
    loss_of_availability: int = _Factor
    loss_of_accountability: int = _Factor


class BusinessImpactFactors(_Factors):
    """Business consequences, from the asset profile."""

    financial_damage: int = _Factor
    reputation_damage: int = _Factor
    non_compliance: int = _Factor
    privacy_violation: int = _Factor


def band(score: float) -> Band:
    """LOW below 3, MEDIUM below 6, otherwise HIGH."""
    if score < 3:
        return "low"
    if score < 6:
        return "medium"
    return "high"


class OwaspRiskRating(KavachModel):
    """A complete OWASP risk rating."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    threat_agent: ThreatAgentFactors
    vulnerability: VulnerabilityFactors
    technical_impact: TechnicalImpactFactors
    business_impact: BusinessImpactFactors
    business_known: bool = False

    @property
    def likelihood_score(self) -> float:
        """Mean of the eight likelihood factors."""
        return round((self.threat_agent.mean() + self.vulnerability.mean()) / 2, 3)

    @property
    def impact_score(self) -> float:
        """Business impact when known, else technical impact."""
        chosen = self.business_impact if self.business_known else self.technical_impact
        return round(chosen.mean(), 3)

    @property
    def likelihood_band(self) -> Band:
        """The likelihood band."""
        return band(self.likelihood_score)

    @property
    def impact_band(self) -> Band:
        """The impact band."""
        return band(self.impact_score)

    @property
    def overall(self) -> Overall:
        """The overall risk severity from the methodology's table."""
        return OVERALL[(self.impact_band, self.likelihood_band)]

    def factors(self) -> tuple[tuple[str, int], ...]:
        """Every factor as ``(name, value)`` pairs, for reports."""
        rows: list[tuple[str, int]] = []
        for group in (
            self.threat_agent,
            self.vulnerability,
            self.technical_impact,
            self.business_impact,
        ):
            rows.extend((name, int(value)) for name, value in group.model_dump().items())
        return tuple(rows)


_CONF: Final = {"H": 7, "L": 6, "N": 0}
_INTEG: Final = {"H": 7, "L": 3, "N": 0}
_AVAIL: Final = {"H": 7, "L": 5, "N": 0}
_ACCOUNT: Final = {"N": 9, "L": 7, "H": 1}


def technical_impact_from(cvss: Cvss4Vector) -> TechnicalImpactFactors:
    """Map CVSS v4.0 impact metrics to OWASP technical impact factors."""
    values = cvss.as_dict

    def worst(vulnerable: str, subsequent: str) -> str:
        order = "HLN"
        first = values.get(vulnerable, "N")
        second = values.get(subsequent, "N")
        second = "H" if second == "S" else second
        return min(first, second, key=order.index)

    conf, integ, avail = worst("VC", "SC"), worst("VI", "SI"), worst("VA", "SA")
    total = conf == integ == avail == "H"
    return TechnicalImpactFactors(
        loss_of_confidentiality=9 if total else _CONF[conf],
        loss_of_integrity=9 if total else _INTEG[integ],
        loss_of_availability=_AVAIL[avail],
        loss_of_accountability=_ACCOUNT[values.get("PR", "N")],
    )


def rate_owasp(
    context: RatingContext,
    *,
    cvss: Cvss4Vector,
    threat: ThreatFactors | None,
    business_known: bool = False,
) -> OwaspRiskRating:
    """An OWASP risk rating from family threat factors, context and the CVSS impact metrics."""
    base = threat or _DEFAULT_THREAT
    opportunity, size = base.opportunity, base.size
    ease_of_exploit = base.ease_of_exploit
    if context.entry_point == "network" and not context.authentication_required:
        opportunity, size = max(opportunity, 9), max(size, 9)
    if context.authentication_required:
        opportunity, size = min(opportunity, 7), min(size, 6)
    if context.entry_point == "local":
        opportunity, size = min(opportunity, 4), min(size, 4)
    if context.is_test_code:
        ease_of_exploit = max(0, ease_of_exploit - 3)
    if context.has_taint_path:
        ease_of_exploit = min(9, ease_of_exploit + 1)
    business = BUSINESS[context.asset_criticality]
    return OwaspRiskRating(
        threat_agent=ThreatAgentFactors(
            skill_level=base.skill, motive=base.motive, opportunity=opportunity, size=size
        ),
        vulnerability=VulnerabilityFactors(
            ease_of_discovery=base.ease_of_discovery,
            ease_of_exploit=ease_of_exploit,
            awareness=base.awareness,
            intrusion_detection=base.intrusion_detection,
        ),
        technical_impact=technical_impact_from(cvss),
        business_impact=BusinessImpactFactors(
            financial_damage=business[0],
            reputation_damage=business[1],
            non_compliance=business[2],
            privacy_violation=business[3],
        ),
        business_known=business_known,
    )
