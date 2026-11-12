"""Cross-engine correlation: one finding when several analysers report the same weakness (#240).

Two candidates describe the same weakness when they are in the same file, share a CWE and sit within
``LINE_WINDOW`` lines of each other, or when they have the same rule and place. The one from the
most trusted analyser (taint with a path, then rules, then external engines, then the rest) is kept;
the others are folded into it: their engines and rule ids are listed in
``aggregate.also_reported_by``
and the kept candidate's confidence rises one step when two or more distinct engines agree.
Secret and misconfiguration candidates are never folded into code findings of another kind.
"""

from typing import Final

from codekavach.core.models import Candidate, Confidence
from codekavach.core.models.enums import CandidateKind

LINE_WINDOW: Final = 2
MAX_LISTED: Final = 6
_PRIORITY: Final = ("codekavach-taint", "codekavach-rules")


def _rank(candidate: Candidate) -> tuple[int, int, int]:
    engine = candidate.engine
    base = _PRIORITY.index(engine) if engine in _PRIORITY else len(_PRIORITY)
    severity = candidate.engine_severity.rank if candidate.engine_severity else 0
    return (0 if candidate.taint_path is not None else 1, base, -severity)


def _same(a: Candidate, b: Candidate) -> bool:
    if a.kind is not b.kind and CandidateKind.VULNERABILITY not in (a.kind, b.kind):
        return False
    if (a.kind is CandidateKind.SECRET) != (b.kind is CandidateKind.SECRET):
        return False
    if (a.kind is CandidateKind.MISCONFIGURATION) != (b.kind is CandidateKind.MISCONFIGURATION):
        return False
    pa, pb = a.primary_location, b.primary_location
    if pa.path != pb.path or abs(pa.start_line - pb.start_line) > LINE_WINDOW:
        return False
    return bool(set(a.cwe) & set(b.cwe))


def _bump(confidence: Confidence | None) -> Confidence:
    if confidence is None or confidence is Confidence.LOW:
        return Confidence.MEDIUM
    return Confidence.HIGH


def correlate(candidates: list[Candidate]) -> list[Candidate]:
    """Fold candidates that several engines report for one weakness; order is preserved."""
    ordered = sorted(candidates, key=_rank)
    kept: list[Candidate] = []
    folded: dict[str, list[Candidate]] = {}
    for candidate in ordered:
        home = next((k for k in kept if k.engine != candidate.engine and _same(k, candidate)), None)
        if home is None:
            kept.append(candidate)
        else:
            folded.setdefault(str(home.id), []).append(candidate)
    result: list[Candidate] = []
    for candidate in kept:
        extra = folded.get(str(candidate.id))
        if not extra:
            result.append(candidate)
            continue
        listed = sorted({f"{c.engine}:{c.rule_id}" for c in extra})[:MAX_LISTED]
        properties = tuple(p for p in candidate.properties if p[0] != "aggregate.also_reported_by")
        properties += (("aggregate.also_reported_by", ",".join(listed)[:500]),)
        engines = {candidate.engine} | {c.engine for c in extra}
        confidence = _bump(candidate.engine_confidence) if len(engines) > 1 else None
        update: dict[str, object] = {"properties": properties}
        if confidence is not None and (
            candidate.engine_confidence is None or confidence > candidate.engine_confidence
        ):
            update["engine_confidence"] = confidence
        result.append(candidate.model_copy(update=update))
    return result
