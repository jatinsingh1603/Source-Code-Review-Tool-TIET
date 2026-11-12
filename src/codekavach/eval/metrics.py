# ruff: noqa: D101, D102, D103
"""Detection metrics with bootstrap confidence intervals (#279).

Counts are over *units*: one unit per labelled vulnerability (found or missed) and one per
in-scope false positive. A bootstrap resamples units with replacement (seeded, so a result is
reproducible) and recomputes precision, recall and F1; the interval is the 2.5th and 97.5th
percentile. With few units the interval is wide, and it is reported as such, not hidden.
"""

import random
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass

from codekavach.eval.datasets import TruthItem
from codekavach.eval.matcher import MatchResult, Reported, family

Interval = tuple[float, float]
BOOTSTRAP_ROUNDS = 1000


@dataclass(frozen=True)
class Counts:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


@dataclass(frozen=True)
class Scored:
    """Counts, point metrics and 95 percent intervals."""

    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    precision_ci: Interval
    recall_ci: Interval
    f1_ci: Interval

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _percentile(values: list[float], q: float) -> float:
    values = sorted(values)
    index = min(len(values) - 1, max(0, round(q * (len(values) - 1))))
    return values[index]


def score(
    tp_units: int, fp_units: int, fn_units: int, *, seed: int = 20260101, rounds: int | None = None
) -> Scored:
    """Metrics of a count triple with a unit-level bootstrap."""
    rounds = BOOTSTRAP_ROUNDS if rounds is None else rounds
    base = Counts(tp_units, fp_units, fn_units)
    units = [0] * tp_units + [1] * fp_units + [2] * fn_units
    if not units:
        zero = (0.0, 0.0)
        return Scored(0, 0, 0, 0.0, 0.0, 0.0, zero, zero, zero)
    rng = random.Random(seed)  # noqa: S311 - resampling, not security
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []
    for _ in range(rounds):
        sample = [units[rng.randrange(len(units))] for _ in units]
        c = Counts(sample.count(0), sample.count(1), sample.count(2))
        precisions.append(c.precision)
        recalls.append(c.recall)
        f1s.append(c.f1)

    def ci(values: list[float]) -> Interval:
        return (round(_percentile(values, 0.025), 4), round(_percentile(values, 0.975), 4))

    return Scored(
        base.tp,
        base.fp,
        base.fn,
        round(base.precision, 4),
        round(base.recall, 4),
        round(base.f1, 4),
        ci(precisions),
        ci(recalls),
        ci(f1s),
    )


def score_result(result: MatchResult, *, rounds: int | None = None) -> Scored:
    return score(
        len(result.matched), len(result.false_positives), len(result.missed), rounds=rounds
    )


def _group(
    result: MatchResult, key: Callable[[TruthItem | Reported], str], *, rounds: int | None
) -> dict[str, Scored]:
    tp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    for item, _ in result.matched:
        tp[key(item)] += 1
    for item in result.missed:
        fn[key(item)] += 1
    for rep in result.false_positives:
        fp[key(rep)] += 1
    return {k: score(tp[k], fp[k], fn[k], rounds=rounds) for k in sorted({*tp, *fn, *fp})}


def _lang(value: TruthItem | Reported) -> str:
    if isinstance(value, TruthItem):
        return value.language
    return TruthItem("", 0, value.file, 0).language


def _cwe(value: TruthItem | Reported) -> str:
    if isinstance(value, TruthItem):
        return f"CWE-{value.cwe}"
    return f"CWE-{value.cwes[0]}" if value.cwes else "CWE-?"


def _family(value: TruthItem | Reported) -> str:
    if isinstance(value, TruthItem):
        return family(value.cwe)
    return family(value.cwes[0]) if value.cwes else "unknown"


def breakdowns(result: MatchResult, *, rounds: int | None = None) -> dict[str, dict[str, Scored]]:
    """Per CWE, per CWE family and per language metrics."""
    return {
        "by_cwe": _group(result, _cwe, rounds=rounds),
        "by_family": _group(result, _family, rounds=rounds),
        "by_language": _group(result, _lang, rounds=rounds),
    }


def to_reported(findings: Sequence[object]) -> list[Reported]:
    """Adapt ``Finding`` objects (duck-typed: ``id``, ``locations``, ``cwe``)."""
    out: list[Reported] = []
    for f in findings:
        locations = getattr(f, "locations", ())
        if not locations:
            continue
        loc = locations[0]
        cwes = tuple(int(str(c).split("-")[-1]) for c in getattr(f, "cwe", ()))
        out.append(Reported(str(f.id), str(loc.path), loc.start_line, loc.end_line, cwes))  # type: ignore[attr-defined]
    return out
