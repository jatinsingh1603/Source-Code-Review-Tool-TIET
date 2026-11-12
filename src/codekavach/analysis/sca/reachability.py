"""Four-valued reachability hint from imports and the call graph (E19-02).

``unreachable``
    the package is not imported anywhere in the scanned code,
``imported``
    it is imported but no advisory-named symbol is called (or the advisory names none),
``called``
    an advisory-named symbol appears as a callee in the parsing call graph,
``unknown``
    the information is unavailable (no source of that language was scanned, or the ecosystem is
    not supported).

This is a hint, never a filter: it sets ``sca.reachability`` and ``sca.reachability_basis``, informs
ordering and confidence, and is stated in the report. Only an operator decision through the shared
baseline or suppression mechanism removes a finding from the report body. The call graph is
name-based and unsound (see ``codekavach.parsing.callgraph``): ``called`` is therefore positive
evidence, while ``imported`` after a symbol search means "not seen called", not "never called".
"""

from dataclasses import dataclass
from typing import Final

from codekavach.analysis.sca.model import Dependency
from codekavach.analysis.sca.reach import Reach, import_names
from codekavach.parsing.callgraph import UNRESOLVED_PREFIX, CallGraph

UNREACHABLE: Final = "unreachable"
IMPORTED: Final = "imported"
CALLED: Final = "called"
UNKNOWN: Final = "unknown"


@dataclass(frozen=True)
class Reachability:
    """The hint, the basis it rests on and the evidence (a call edge or an import site)."""

    status: str
    basis: str
    evidence: str | None = None


def _callee_matches(callee: str, names: set[str], symbols: set[str]) -> bool:
    callee = callee.removeprefix(UNRESOLVED_PREFIX)
    for name in names:
        if callee == name or callee.startswith(name + "."):
            tail = callee[len(name) :].lstrip(".")
            if any(part in symbols for part in tail.split(".") if part):
                return True
    return False


def classify(
    dep: Dependency,
    reach: Reach,
    symbols: tuple[str, ...] = (),
    graph: CallGraph | None = None,
) -> Reachability:
    """The hint for one component, given its import evidence and (optionally) the call graph."""
    if reach.status == "unknown":
        return Reachability(UNKNOWN, "no source of this ecosystem was scanned")
    if reach.status == "not_imported":
        return Reachability(UNREACHABLE, "package is not imported anywhere in the scanned code")
    site = f"{reach.path}:{reach.line}" if reach.path else None
    if not symbols:
        return Reachability(IMPORTED, "module-level import (the advisory names no symbols)", site)
    if graph is None:
        return Reachability(IMPORTED, "module-level import (no call graph available)", site)
    names = import_names(dep)
    wanted = set(symbols)
    for caller, callee in graph.edges:
        if _callee_matches(callee, names, wanted):
            return Reachability(
                CALLED, "advisory-named symbol in the call graph", f"{caller} -> {callee}"
            )
    return Reachability(IMPORTED, "imported; no advisory-named symbol seen in the call graph", site)
