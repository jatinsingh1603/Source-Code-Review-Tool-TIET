"""Finding matcher: file + line window + CWE family (#278).

A reported finding matches a labelled vulnerability when it is in the same file, within
``window`` lines of the label (any line when the label is file-level, ``line == 0``), and its CWE
is in the same family as the label's. Each label is matched by at most one finding (the closest);
extra findings on the same label are *duplicates*, not false positives. A finding is a false
positive when it is in scope (its CWE family is one the dataset labels) and matches nothing; a
finding whose family the dataset never labels is *out of scope* and neither helps nor hurts.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final

from codekavach.eval.datasets import SOURCE_SUFFIXES, TruthItem

FAMILIES: Final[dict[str, frozenset[int]]] = {
    "injection-sql": frozenset({89, 564, 943, 566}),
    "injection-os": frozenset({77, 78, 88, 94, 95, 917}),
    "path": frozenset({22, 23, 36, 73, 59}),
    "ssrf": frozenset({918}),
    "deserialisation": frozenset({502}),
    "crypto": frozenset({326, 327, 328, 329, 330, 331, 338, 916, 759, 760}),
    "authz": frozenset({284, 285, 639, 862, 863, 566}),
    "xss": frozenset({79, 80, 83, 87}),
    "secrets": frozenset({798, 259, 321, 312, 256, 522, 540}),
    "xxe": frozenset({611, 776}),
    "redirect": frozenset({601}),
    "ldap-xpath": frozenset({90, 643}),
    "session": frozenset({352, 614, 1004, 330, 384}),
    "trust-boundary": frozenset({501}),
    "memory": frozenset({119, 120, 121, 122, 125, 787, 415, 416, 476}),
}


def family(cwe: int) -> str:
    """The family of a CWE id, or ``cwe-<id>`` when it belongs to none."""
    for name, members in FAMILIES.items():
        if cwe in members:
            return name
    return f"cwe-{cwe}"


@dataclass(frozen=True)
class Reported:
    """The part of a finding the matcher needs."""

    id: str
    file: str
    start: int
    end: int
    cwes: tuple[int, ...]


@dataclass
class MatchResult:
    """The outcome of matching one set of findings against one set of labels."""

    matched: list[tuple[TruthItem, Reported]] = field(default_factory=list)
    missed: list[TruthItem] = field(default_factory=list)
    false_positives: list[Reported] = field(default_factory=list)
    on_controls: list[tuple[TruthItem, Reported]] = field(default_factory=list)
    duplicates: int = 0
    out_of_scope: int = 0


def _same_family(item: TruthItem, cwes: Iterable[int]) -> bool:
    wanted = family(item.cwe)
    return any(c == item.cwe or family(c) == wanted for c in cwes)


def _near(item: TruthItem, rep: Reported, window: int) -> bool:
    if item.file != rep.file:
        return False
    if item.line == 0:
        return True
    return rep.start - window <= item.line <= rep.end + window


def match(
    truth: Sequence[TruthItem], reported: Sequence[Reported], *, window: int = 3
) -> MatchResult:
    """Match ``reported`` findings against ``truth`` labels."""
    result = MatchResult()
    vulns = [t for t in truth if t.kind == "vulnerability"]
    controls = [t for t in truth if t.kind == "safe"]
    scope = {family(t.cwe) for t in vulns}
    taken: dict[str, tuple[TruthItem, Reported]] = {}
    used: set[str] = set()
    for rep in sorted(reported, key=lambda r: (r.file, r.start, r.id)):
        if not rep.file.lower().endswith(tuple(SOURCE_SUFFIXES)):
            result.out_of_scope += 1  # manifests, lock files: dependency advisories, not SAST
            continue
        candidates = [t for t in vulns if _near(t, rep, window) and _same_family(t, rep.cwes)]
        if candidates:
            best = min(candidates, key=lambda t: abs(t.line - rep.start) if t.line else 0)
            if best.id in taken:
                result.duplicates += 1
            else:
                taken[best.id] = (best, rep)
            used.add(rep.id)
            continue
        control = next((c for c in controls if _near(c, rep, 0) and c.line != 0), None)
        if control is not None and any(
            family(c) == family(control.cwe) or control.cwe == 0 for c in rep.cwes
        ):
            result.on_controls.append((control, rep))
            result.false_positives.append(rep)
            continue
        if any(family(c) in scope for c in rep.cwes):
            result.false_positives.append(rep)
        else:
            result.out_of_scope += 1
    result.matched = [taken[t.id] for t in vulns if t.id in taken]
    result.missed = [t for t in vulns if t.id not in taken]
    return result
