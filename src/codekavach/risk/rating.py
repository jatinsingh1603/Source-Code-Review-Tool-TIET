"""The rating engine: one candidate and its context become CVSS, OWASP, matrix and severity.

Owning epic: E29. ``RatingEngine.rate`` is deterministic: the same candidate and context always
produce the same rating. It reads the weakness family from the knowledge base (falling back to a
generic family when the CWE is unknown or the data files are absent), proposes CVSS v4.0 and v3.1
Base vectors adjusted by code evidence, scores them, rates the OWASP likelihood and impact, places
the finding on the five-by-five matrix and maps the result to a severity under the policy.
"""

from dataclasses import dataclass
from typing import Final

from codekavach.core.log import get_logger
from codekavach.core.models.enums import Confidence, Severity
from codekavach.core.models.finding import RiskRating
from codekavach.risk.context import RatingContext
from codekavach.risk.cvss.v4 import Cvss4Vector
from codekavach.risk.cvss.v31 import Cvss31Vector
from codekavach.risk.matrix import MatrixCell, to_cell
from codekavach.risk.owasp import OwaspRiskRating, rate_owasp
from codekavach.risk.severity import (
    DEFAULT_POLICY,
    SeverityPolicy,
    apply_model_downgrade,
    severity_from_rating,
)
from codekavach.risk.taxonomy.loader import CweEntry, Family, KnowledgeBase
from codekavach.risk.templates import base_vectors_for

_log = get_logger(__name__)

METHOD_VERSION: Final = "e29-1"


@dataclass(frozen=True, slots=True)
class RatingResult:
    """Everything the rating decided about one candidate."""

    context: RatingContext
    cvss4: Cvss4Vector
    cvss4_score: float
    cvss31: Cvss31Vector
    cvss31_score: float
    metric_rationale: tuple[tuple[str, str], ...]
    adjustments: tuple[str, ...]
    owasp: OwaspRiskRating
    cell: MatrixCell
    severity: Severity
    confidence: Confidence
    family: Family | None
    entry: CweEntry | None
    knowledge_base_version: str | None
    policy_source: str = "cvss4"

    @property
    def nomenclature(self) -> str:
        """CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE."""
        return self.cvss4.nomenclature()

    def to_risk(self) -> RiskRating:
        """The ``Finding.risk`` record."""
        return RiskRating(
            method_version=METHOD_VERSION,
            cvss4_nomenclature=self.nomenclature,
            cvss4_macrovector=self.cvss4.macrovector(),
            metric_rationale=self.metric_rationale,
            adjustments=self.adjustments,
            owasp_likelihood=self.owasp.likelihood_score,
            owasp_impact=self.owasp.impact_score,
            owasp_likelihood_band=self.owasp.likelihood_band,
            owasp_impact_band=self.owasp.impact_band,
            owasp_overall=self.owasp.overall,
            owasp_factors=self.owasp.factors(),
            matrix_label=self.cell.label,
            severity_source=(
                "engine" if "policy:engine_severity" in self.adjustments else self.policy_source
            ),
            engine_severity=self.context.engine_severity,
            family=self.family.key if self.family else None,
            cwe_name=self.entry.name[:300] if self.entry else None,
            top25_rank=self.entry.top25 if self.entry else None,
            knowledge_base_version=self.knowledge_base_version,
        )


class RatingEngine:
    """Rates candidates with a knowledge base (optional) and a severity policy."""

    def __init__(
        self,
        knowledge_base: KnowledgeBase | None,
        *,
        policy: SeverityPolicy = DEFAULT_POLICY,
        business_known: bool = False,
    ) -> None:
        self.knowledge_base = knowledge_base
        self.policy = policy
        self.business_known = business_known

    def rate(
        self,
        context: RatingContext,
        *,
        confidence: Confidence,
        model_is_vulnerable: bool | None = None,
        model_confidence: Confidence | None = None,
    ) -> RatingResult:
        """Rate one candidate described by ``context``."""
        kb = self.knowledge_base
        entry = kb.primary(context.cwe) if kb is not None else None
        family = kb.family_for(context.cwe) if kb is not None else None
        cvss4, cvss31, rationale, adjustments = base_vectors_for(context, family)
        score4 = cvss4.score()
        owasp = rate_owasp(
            context,
            cvss=cvss4,
            threat=family.threat if family else None,
            business_known=self.business_known,
        )
        cell = to_cell(owasp, cvss_score=score4, confidence=confidence)
        draft = RatingResult(
            context=context,
            cvss4=cvss4,
            cvss4_score=score4,
            cvss31=cvss31,
            cvss31_score=cvss31.base_score(),
            metric_rationale=rationale,
            adjustments=adjustments,
            owasp=owasp,
            cell=cell,
            severity=Severity.INFO,
            confidence=confidence,
            family=family,
            entry=entry,
            knowledge_base_version=kb.catalogue_version if kb is not None else None,
            policy_source=self.policy.source,
        )
        severity, steps = severity_from_rating(draft, self.policy)
        severity, downgraded = apply_model_downgrade(
            severity, model_is_vulnerable, model_confidence, self.policy
        )
        if downgraded:
            steps = (*steps, "policy:model_downgrade")
        return RatingResult(
            **{
                **{name: getattr(draft, name) for name in RatingResult.__slots__},
                "severity": severity,
                "adjustments": (*adjustments, *steps),
            }
        )
