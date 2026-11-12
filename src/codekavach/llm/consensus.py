"""LLM consensus and confidence calibration (E23-03, issue 247).

Owning epic: E23. Normative layout: docs/ARCHITECTURE.md section 3.

``vote`` combines several triage verdicts for one candidate (N samples of one model with
different review perspectives, or one verdict per provider) into one. The rules are chosen so
that a model can never talk a finding out of existence:

* a majority of *decided* verdicts (true or false) wins; an abstention (``is_vulnerable`` null)
  counts for neither side;
* a tie goes to ``vulnerable`` with the confidence capped at low: disagreement means a human
  should look, and the finding stays;
* the representative verdict is the most confident one on the winning side, its CWEs are the ones
  at least half of the winning side named, and ``agreement`` is the winning share of the decided
  verdicts.

``calibrate`` turns a stated confidence into a more honest one. A model's "high" is cheap, so the
number is scaled by the agreement between samples and reduced when the input showed signs of
steering. The result is never higher than one step above what the model stated.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from codekavach.core.models.enums import Confidence
from codekavach.core.models.verdict import LLMVerdict

_SCORE: Final = {Confidence.LOW: 0.35, Confidence.MEDIUM: 0.6, Confidence.HIGH: 0.85}
_ORDER: Final = (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)
INJECTION_FACTOR: Final = 0.7


@dataclass(frozen=True, slots=True)
class ConsensusResult:
    """The combined verdict and how the samples voted."""

    verdict: LLMVerdict
    samples: int
    agreement: float
    votes_vulnerable: int
    votes_safe: int
    abstained: int
    tie: bool


def vote(verdicts: Sequence[LLMVerdict]) -> ConsensusResult:
    """Combine ``verdicts`` (at least one) into one.

    Raises:
        ValueError: ``verdicts`` is empty.
    """
    if not verdicts:
        raise ValueError("vote needs at least one verdict")
    yes = [v for v in verdicts if v.is_vulnerable is True]
    no = [v for v in verdicts if v.is_vulnerable is False]
    abstained = len(verdicts) - len(yes) - len(no)
    if not yes and not no:
        return ConsensusResult(verdicts[0], len(verdicts), 0.0, 0, 0, abstained, False)
    tie = len(yes) == len(no)
    winners = yes if len(yes) >= len(no) else no
    best = max(winners, key=lambda item: _ORDER.index(item.confidence))
    counts = Counter(number for item in winners for number in item.cwe)
    cwe = (
        tuple(number for number, count in counts.most_common() if count * 2 >= len(winners))
        or best.cwe
    )
    confidence = Confidence.LOW if tie else best.confidence
    merged = best.model_copy(update={"cwe": cwe[:5], "confidence": confidence})
    decided = len(yes) + len(no)
    return ConsensusResult(
        verdict=merged,
        samples=len(verdicts),
        agreement=len(winners) / decided if not tie else 0.5,
        votes_vulnerable=len(yes),
        votes_safe=len(no),
        abstained=abstained,
        tie=tie,
    )


def calibrate(
    stated: Confidence,
    *,
    agreement: float = 1.0,
    samples: int = 1,
    injection_suspected: bool = False,
) -> Confidence:
    """A confidence adjusted for sample agreement and signs of steering in the input."""
    score = _SCORE[stated]
    if samples > 1:
        score *= 0.5 + 0.5 * max(0.0, min(agreement, 1.0))
        if samples >= 3 and agreement >= 0.999:
            score = min(score * 1.1, 0.9)
    if injection_suspected:
        score *= INJECTION_FACTOR
    result = Confidence.LOW
    if score >= 0.75:
        result = Confidence.HIGH
    elif score >= 0.45:
        result = Confidence.MEDIUM
    # Never more than one notch above what the model itself stated.
    ceiling = _ORDER[min(_ORDER.index(stated) + 1, 2)]
    return result if _ORDER.index(result) <= _ORDER.index(ceiling) else ceiling
