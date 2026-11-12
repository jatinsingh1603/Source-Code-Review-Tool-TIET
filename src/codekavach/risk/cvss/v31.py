"""CVSS v3.1 vectors and Base scoring, implemented from the FIRST specification.

Owning epic: E29. Formulas and weights are those of the CVSS v3.1 Specification Document,
section 7 and Appendix A (FIRST, June 2019), including the floating-point safe Roundup. Temporal
and Environmental metrics are parsed and preserved; only the Base score is computed.
"""

import math
from dataclasses import dataclass
from typing import Final

from codekavach.core.log import get_logger
from codekavach.core.models.enums import Severity
from codekavach.risk.cvss.v4 import qualitative
from codekavach.risk.cvss.vector import CvssVectorError, format_metrics, parse_metrics

_log = get_logger(__name__)

PREFIX: Final = "CVSS:3.1"
BASE_METRICS: Final = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
TEMPORAL_METRICS: Final = ("E", "RL", "RC")
ENVIRONMENTAL_METRICS: Final = (
    "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
)  # fmt: skip
ORDER: Final = BASE_METRICS + TEMPORAL_METRICS + ENVIRONMENTAL_METRICS

_F = frozenset
VALUES: Final[dict[str, frozenset[str]]] = {
    "AV": _F("NALP"), "AC": _F("LH"), "PR": _F("NLH"), "UI": _F("NR"), "S": _F("UC"),
    "C": _F("HLN"), "I": _F("HLN"), "A": _F("HLN"),
    "E": _F("XUPFH"), "RL": _F("XOTWU"), "RC": _F("XURC"),
    "CR": _F("XLMH"), "IR": _F("XLMH"), "AR": _F("XLMH"),
    "MAV": _F("XNALP"), "MAC": _F("XLH"), "MPR": _F("XNLH"), "MUI": _F("XNR"), "MS": _F("XUC"),
    "MC": _F("XNLH"), "MI": _F("XNLH"), "MA": _F("XNLH"),
}  # fmt: skip

_AV: Final = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC: Final = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: Final = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Final = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI: Final = {"N": 0.85, "R": 0.62}
_CIA: Final = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(value: float) -> float:
    """CVSS v3.1 Appendix A Roundup: the smallest one-decimal number >= value."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score_v31(metrics: dict[str, str]) -> float:
    """The CVSS v3.1 Base score of a metric mapping."""
    changed = metrics["S"] == "C"
    iss = 1 - ((1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]]))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[metrics["PR"]]
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


@dataclass(frozen=True, slots=True)
class Cvss31Vector:
    """A parsed CVSS v3.1 vector; immutable."""

    metrics: tuple[tuple[str, str], ...]

    @classmethod
    def parse(cls, text: str) -> "Cvss31Vector":
        """Parse ``text`` (metrics in any order, as v3.1 allows); raises CvssVectorError."""
        parsed = parse_metrics(
            text,
            prefix=PREFIX,
            order=ORDER,
            values=VALUES,
            mandatory=BASE_METRICS,
            ordered=False,
        )
        return cls(tuple((key, parsed[key]) for key in ORDER if key in parsed))

    @classmethod
    def from_metrics(cls, metrics: dict[str, str]) -> "Cvss31Vector":
        """Build from a metric mapping, validating it like a parsed string."""
        return cls.parse(
            format_metrics(metrics, prefix=PREFIX, order=ORDER, mandatory=BASE_METRICS)
        )

    @property
    def as_dict(self) -> dict[str, str]:
        """The metrics as a dictionary."""
        return dict(self.metrics)

    def to_string(self) -> str:
        """The canonical vector string in specification order (``X`` values omitted)."""
        return format_metrics(self.as_dict, prefix=PREFIX, order=ORDER, mandatory=BASE_METRICS)

    def __str__(self) -> str:
        return self.to_string()

    def base_score(self) -> float:
        """The Base score, 0.0 to 10.0."""
        return base_score_v31(self.as_dict)

    def severity(self) -> Severity:
        """The qualitative severity rating of the Base score."""
        return qualitative(self.base_score())


def try_parse(text: str | None) -> Cvss31Vector | None:
    """Parse ``text`` or return None when it is missing or invalid."""
    if not text:
        return None
    try:
        return Cvss31Vector.parse(text)
    except CvssVectorError:
        return None
