"""The five-by-five risk matrix: likelihood and impact levels and the label of each cell.

Owning epic: E29. Impact level follows the CVSS v4.0 score on the FIRST qualitative scale
(none 1, low 2, medium 3, high 4, critical 5). Likelihood level follows the OWASP likelihood score
(0 to 9 split into five equal steps), one step lower when detection confidence is low. The cell
label is read from the product of the two levels: up to 4 low, up to 9 medium, up to 16 high,
20 and 25 critical. This is CodeKavach's method, printed in the report's rating appendix.
"""

import math
from typing import ClassVar, Final

from pydantic import Field

from codekavach.core.log import get_logger
from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.enums import Confidence
from codekavach.risk.owasp import OwaspRiskRating

_log = get_logger(__name__)

LEVEL_LABELS: Final = ("very low", "low", "moderate", "high", "very high")


def cell_label(likelihood: int, impact: int) -> str:
    """The qualitative label of a matrix cell."""
    product = likelihood * impact
    if product <= 4:
        return "low"
    if product <= 9:
        return "medium"
    if product <= 16:
        return "high"
    return "critical"


MATRIX_SEVERITY: Final[dict[tuple[int, int], str]] = {
    (likelihood, impact): cell_label(likelihood, impact)
    for likelihood in range(1, 6)
    for impact in range(1, 6)
}


class MatrixCell(KavachModel):
    """A position on the five-by-five matrix."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    likelihood_level: int = Field(ge=1, le=5)
    impact_level: int = Field(ge=1, le=5)

    @property
    def label(self) -> str:
        """The cell's qualitative label."""
        return MATRIX_SEVERITY[(self.likelihood_level, self.impact_level)]


def impact_level(cvss_score: float) -> int:
    """Impact level 1 to 5 from a CVSS score."""
    if cvss_score <= 0.0:
        return 1
    if cvss_score < 4.0:
        return 2
    if cvss_score < 7.0:
        return 3
    if cvss_score < 9.0:
        return 4
    return 5


def likelihood_level(owasp_likelihood: float, confidence: Confidence) -> int:
    """Likelihood level 1 to 5 from the OWASP likelihood score and detection confidence."""
    level = min(5, max(1, math.ceil(owasp_likelihood / 1.8)))
    if confidence is Confidence.LOW:
        level = max(1, level - 1)
    return level


def to_cell(rating: OwaspRiskRating, *, cvss_score: float, confidence: Confidence) -> MatrixCell:
    """The matrix cell of a finding."""
    return MatrixCell(
        likelihood_level=likelihood_level(rating.likelihood_score, confidence),
        impact_level=impact_level(cvss_score),
    )
