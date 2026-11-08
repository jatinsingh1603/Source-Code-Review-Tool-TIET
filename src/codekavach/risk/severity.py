"""Severity of a candidate: the CVSS score when there is one, else the engine's, else the CWE's.

Owning epic: E13. MVP; extended by E29, which adds CVSS v4.0 vector computation, the OWASP risk
rating and the compliance mappings. Until then a score is read from the ``cvss4_score`` property an
engine may attach to a candidate; a vector is never computed here.

The model's verdict never changes the severity. A "not vulnerable" answer lowers a finding's
confidence (see ``codekavach.risk.stage``) and is recorded, but a plausible rationale is not proof
of a false positive (``docs/research/INSIGHTS.md`` section 2.2 item 3).
"""

import math
from typing import Final

from codekavach.core.models.candidate import Candidate
from codekavach.core.models.enums import Severity
from codekavach.core.models.verdict import LLMVerdict

SCORE_PROPERTY: Final = "cvss4_score"

# A small table of CWE families, used only when neither a score nor an engine severity exists.
_CWE_DEFAULTS: Final[dict[int, Severity]] = {
    **dict.fromkeys((77, 78, 89, 94, 95, 502, 611, 918), Severity.HIGH),  # injection, deserialise
    **dict.fromkeys((259, 321, 798), Severity.HIGH),  # hard-coded credentials and keys
    **dict.fromkeys((22, 79, 287, 306, 352, 434, 639, 862, 863), Severity.MEDIUM),
    **dict.fromkeys((326, 327, 328, 330, 338), Severity.MEDIUM),  # weak cryptography
    **dict.fromkeys((200, 209, 532, 778), Severity.LOW),  # information exposure, logging
}
FALLBACK: Final = Severity.MEDIUM


def _score_of(candidate: Candidate) -> float | None:
    for key, value in candidate.properties:
        if key == SCORE_PROPERTY:
            try:
                score = float(value)
            except ValueError:
                return None
            return score if math.isfinite(score) and 0.0 <= score <= 10.0 else None
    return None


def map_severity(candidate: Candidate, verdict: LLMVerdict | None) -> Severity:
    """The severity of ``candidate``: its CVSS score, else its engine severity, else its CWE.

    ``verdict`` is accepted so the contract matches what E29 extends; the MVP does not let a model
    answer move the severity in either direction.
    """
    del verdict
    score = _score_of(candidate)
    if score is not None:
        return Severity.from_cvss_score(score)
    if candidate.engine_severity is not None:
        return candidate.engine_severity
    for cwe in candidate.cwe:
        if cwe in _CWE_DEFAULTS:
            return _CWE_DEFAULTS[cwe]
    return FALLBACK
