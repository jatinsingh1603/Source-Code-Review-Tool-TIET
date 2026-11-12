"""CVSS v4.0 vectors and scoring, implemented from the FIRST specification.

Owning epic: E29. Scoring follows the CVSS v4.0 Specification Document, section 8: derive the six
equivalence classes (the macrovector), look up its score, compute the severity distance of the
vector from the highest-severity vectors of the macrovector, take the mean of the proportional
distances to the next lower macrovectors, subtract it, clamp to [0, 10] and round to one decimal.
The algorithm mirrors the FIRST reference calculator so scores match it exactly.
"""

import math
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Final, Literal

from codekavach.core.log import get_logger
from codekavach.core.models.enums import Severity
from codekavach.risk.cvss import _v4_tables as tables
from codekavach.risk.cvss.vector import CvssVectorError, format_metrics, parse_metrics

_log = get_logger(__name__)

PREFIX: Final = "CVSS:4.0"
BASE_METRICS: Final = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
THREAT_METRICS: Final = ("E",)
ENVIRONMENTAL_METRICS: Final = (
    "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
)  # fmt: skip
SUPPLEMENTAL_METRICS: Final = ("S", "AU", "R", "V", "RE", "U")
ORDER: Final = BASE_METRICS + THREAT_METRICS + ENVIRONMENTAL_METRICS + SUPPLEMENTAL_METRICS

_F = frozenset
VALUES: Final[dict[str, frozenset[str]]] = {
    "AV": _F("NALP"), "AC": _F("LH"), "AT": _F("NP"), "PR": _F("NLH"), "UI": _F("NPA"),
    "VC": _F("HLN"), "VI": _F("HLN"), "VA": _F("HLN"),
    "SC": _F("HLN"), "SI": _F("HLN"), "SA": _F("HLN"),
    "E": _F("XAPU"),
    "CR": _F("XHML"), "IR": _F("XHML"), "AR": _F("XHML"),
    "MAV": _F("XNALP"), "MAC": _F("XLH"), "MAT": _F("XNP"), "MPR": _F("XNLH"), "MUI": _F("XNPA"),
    "MVC": _F("XHLN"), "MVI": _F("XHLN"), "MVA": _F("XHLN"),
    "MSC": _F("XHLN"), "MSI": _F("XSHLN"), "MSA": _F("XSHLN"),
    "S": _F("XNP"), "AU": _F("XNY"), "R": _F("XAUI"), "V": _F("XDC"), "RE": _F("XLMH"),
    "U": _F({"X", "Clear", "Green", "Amber", "Red"}),
}  # fmt: skip

_LEVELS: Final[dict[str, dict[str, float]]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

Nomenclature = Literal["CVSS-B", "CVSS-BE", "CVSS-BT", "CVSS-BTE"]


def _split(vector: str) -> dict[str, str]:
    return dict(token.split(":", 1) for token in vector.strip("/").split("/") if token)


@dataclass(frozen=True, slots=True)
class Cvss4Vector:
    """A parsed CVSS v4.0 vector; immutable."""

    metrics: tuple[tuple[str, str], ...]

    @classmethod
    def parse(cls, text: str) -> "Cvss4Vector":
        """Parse ``text``; raises CvssVectorError when it is not a valid v4.0 vector."""
        parsed = parse_metrics(
            text, prefix=PREFIX, order=ORDER, values=VALUES, mandatory=BASE_METRICS
        )
        return cls(tuple((key, parsed[key]) for key in ORDER if key in parsed))

    @classmethod
    def from_metrics(cls, metrics: dict[str, str]) -> "Cvss4Vector":
        """Build from a metric mapping, validating it like a parsed string."""
        return cls.parse(
            format_metrics(metrics, prefix=PREFIX, order=ORDER, mandatory=BASE_METRICS)
        )

    @property
    def as_dict(self) -> dict[str, str]:
        """The metrics as a dictionary."""
        return dict(self.metrics)

    def get(self, key: str) -> str:
        """The raw value of ``key`` (``X`` when it is optional and not given)."""
        return self.as_dict.get(key, "X")

    def with_metrics(self, **changes: str) -> "Cvss4Vector":
        """A copy with ``changes`` applied."""
        return Cvss4Vector.from_metrics({**self.as_dict, **changes})

    def to_string(self) -> str:
        """The canonical vector string (``X`` values omitted)."""
        return format_metrics(self.as_dict, prefix=PREFIX, order=ORDER, mandatory=BASE_METRICS)

    def __str__(self) -> str:
        return self.to_string()

    def nomenclature(self) -> Nomenclature:
        """CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE, by which metric groups are set."""
        values = self.as_dict
        threat = values.get("E", "X") != "X"
        env = any(values.get(key, "X") != "X" for key in ENVIRONMENTAL_METRICS)
        if threat and env:
            return "CVSS-BTE"
        if threat:
            return "CVSS-BT"
        if env:
            return "CVSS-BE"
        return "CVSS-B"

    def score(self) -> float:
        """The CVSS v4.0 score, 0.0 to 10.0 with one decimal."""
        return score_v4(self.as_dict)

    def severity(self) -> Severity:
        """The qualitative severity rating of the score."""
        return qualitative(self.score())

    def macrovector(self) -> str:
        """The six equivalence-class digits."""
        return macrovector(self.as_dict)


def qualitative(score: float) -> Severity:
    """FIRST qualitative scale: None 0.0 (reported as info), Low, Medium, High, Critical."""
    if score <= 0.0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def _m(selected: dict[str, str], metric: str) -> str:
    """Effective value: modified metrics override base ones; unset E, CR, IR, AR are worst case."""
    value = selected.get(metric, "X")
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = selected.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value


def macrovector(selected: dict[str, str]) -> str:
    """The macrovector (EQ1..EQ6 digits) of a metric mapping."""
    av, pr, ui = _m(selected, "AV"), _m(selected, "PR"), _m(selected, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if _m(selected, "AC") == "L" and _m(selected, "AT") == "N" else 1
    vc, vi, va = _m(selected, "VC"), _m(selected, "VI"), _m(selected, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif "H" in (vc, vi, va):
        eq3 = 1
    else:
        eq3 = 2
    if _m(selected, "MSI") == "S" or _m(selected, "MSA") == "S":
        eq4 = 0
    elif "H" in (_m(selected, "SC"), _m(selected, "SI"), _m(selected, "SA")):
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[_m(selected, "E")]
    high_requirement = (
        (_m(selected, "CR") == "H" and vc == "H")
        or (_m(selected, "IR") == "H" and vi == "H")
        or (_m(selected, "AR") == "H" and va == "H")
    )
    eq6 = 0 if high_requirement else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _lookup(eqs: tuple[int, ...]) -> float:
    return tables.LOOKUP.get("".join(str(e) for e in eqs), math.nan)


def score_v4(selected: dict[str, str]) -> float:
    """Score a v4.0 metric mapping exactly as the FIRST reference calculator does."""
    if all(_m(selected, metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = macrovector(selected)
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(digit) for digit in macro)
    value = tables.LOOKUP[macro]

    lower_eq1 = _lookup((eq1 + 1, eq2, eq3, eq4, eq5, eq6))
    lower_eq2 = _lookup((eq1, eq2 + 1, eq3, eq4, eq5, eq6))
    if eq3 == 0 and eq6 == 0:
        left = _lookup((eq1, eq2, eq3, eq4, eq5, eq6 + 1))
        right = _lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6))
        lower_eq3eq6 = left if left > right else right
    elif eq3 == 1 and eq6 == 0:
        lower_eq3eq6 = _lookup((eq1, eq2, eq3, eq4, eq5, eq6 + 1))
    elif eq6 == 1 and eq3 in (0, 1):
        lower_eq3eq6 = _lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    else:
        lower_eq3eq6 = _lookup((eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))
    lower_eq4 = _lookup((eq1, eq2, eq3, eq4 + 1, eq5, eq6))
    lower_eq5 = _lookup((eq1, eq2, eq3, eq4, eq5 + 1, eq6))

    max_vectors = [
        a + b + c + d + e
        for a in tables.MAX_COMPOSED_EQ1[eq1]
        for b in tables.MAX_COMPOSED_EQ2[eq2]
        for c in tables.MAX_COMPOSED_EQ3[eq3][eq6]
        for d in tables.MAX_COMPOSED_EQ4[eq4]
        for e in tables.MAX_COMPOSED_EQ5[eq5]
    ]
    distances: dict[str, float] = {}
    for candidate in max_vectors:
        maximal = _split(candidate)
        distances = {
            metric: levels[_m(selected, metric)] - levels[maximal[metric]]
            for metric, levels in _LEVELS.items()
        }
        if all(distance >= 0 for distance in distances.values()):
            break

    current_eq1 = distances["AV"] + distances["PR"] + distances["UI"]
    current_eq2 = distances["AC"] + distances["AT"]
    current_eq3eq6 = sum(distances[m] for m in ("VC", "VI", "VA", "CR", "IR", "AR"))
    current_eq4 = distances["SC"] + distances["SI"] + distances["SA"]

    step = 0.1
    parts: list[float] = []
    for lower, current, depth in (
        (lower_eq1, current_eq1, tables.MAX_SEVERITY_EQ1[eq1] * step),
        (lower_eq2, current_eq2, tables.MAX_SEVERITY_EQ2[eq2] * step),
        (lower_eq3eq6, current_eq3eq6, tables.MAX_SEVERITY_EQ3EQ6[eq3][eq6] * step),
        (lower_eq4, current_eq4, tables.MAX_SEVERITY_EQ4[eq4] * step),
        (lower_eq5, 0.0, 1.0),
    ):
        available = value - lower
        if math.isnan(available):
            continue
        parts.append(available * (current / depth))
    mean = sum(parts) / len(parts) if parts else 0.0
    result = min(max(value - mean, 0.0), 10.0)
    return round_half_up(result)


EPSILON: Final = 1e-6


def round_half_up(value: float) -> float:
    """Round half up to one decimal, absorbing float error (8.6 - 7.15 must round to 1.5).

    The FIRST calculator's revised rounding adds a small epsilon before rounding half up; the
    Red Hat reference library does the same with Decimal, and both agree with this function.
    """
    return float(Decimal(value + EPSILON).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def try_parse(text: str | None) -> Cvss4Vector | None:
    """Parse ``text`` or return None when it is missing or invalid."""
    if not text:
        return None
    try:
        return Cvss4Vector.parse(text)
    except CvssVectorError:
        return None
