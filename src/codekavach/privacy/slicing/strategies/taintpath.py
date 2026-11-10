"""The taint-path slice strategy (E11-03).

Owning epic: E11.

For a candidate that carries a ``TaintPath`` the strategy takes, for each step of the path, the
statement that contains it, the statements that define the variables the step reads, and every
control-dependence ancestor of the step inside its function (the compound statements around it and
the early-exit guards before it). Steps are cut as code up to ``privacy.slice.callee_depth``
function hops from the candidate's own function; functions beyond that become signature stubs.

On the worked example of the issue (a request value that reaches a ``cur.execute`` behind an
``if not is_admin(...): raise`` guard) the slice is the source statement, the sink, the guard with
its ``raise``, and nothing else of the function.

Statements nearer the sink rank higher, then definitions nearer the sink; when the slice is over
budget the furthest go first, and the candidate's statement and everything that controls it never
do (``pathslice``). Without a ``TaintPath`` the strategy is not applicable (``no_taint_path``).
"""

from codekavach.core.models import Candidate, CodeSlice, Location, SliceStrategy
from codekavach.privacy.slicing.base import NotApplicableError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.interproc import partition_by_depth
from codekavach.privacy.slicing.pathslice import Anchor, PathPlan, build_path_slice
from codekavach.privacy.slicing.stubs import StubStats

DEFAULT_CALLEE_DEPTH = 1


def definitions_of_reads(parsed: ParseIndex, location: Location) -> list[Location]:
    """The statements that define what the statement at ``location`` reads (one hop)."""
    if not parsed.has_parsed(location.path):
        return []
    flow = parsed.defuse_of(location.path).flow_for(location)
    if flow is None:
        return []
    index = flow.statement_at(location.start_line)
    if index is None:
        return []
    found: dict[int, None] = {}
    for key in flow.reads_of(index, within=location):
        for definition in flow.reaching(index, key):
            if definition != index:
                found.setdefault(definition)
    return [flow.location_of(d) for d in found]


class TaintPathStrategy:
    """Cuts the steps of a taint path, what they read and what controls them."""

    name = SliceStrategy.TAINT_PATH

    def __init__(self, *, callee_depth: int = DEFAULT_CALLEE_DEPTH) -> None:
        self._depth = callee_depth

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``; ``NotApplicableError`` when it has no taint path."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs."""
        path = candidate.taint_path
        if path is None:
            raise NotApplicableError("no_taint_path")
        hops = partition_by_depth(parsed, path.steps, self._depth)
        if not hops.near:
            raise NotApplicableError("unresolved_path")
        count = len(path.steps)
        anchors: list[Anchor] = []
        found: set[tuple[str, int]] = set()
        for distance, step in enumerate(reversed(hops.near)):
            anchors.append(Anchor(step.location, distance, "step"))
            for definition in definitions_of_reads(parsed, step.location):
                key = (definition.path, definition.start_line)
                if key not in found:
                    found.add(key)
                    anchors.append(Anchor(definition, count + distance, "defuse"))
        plan = PathPlan(
            strategy=self.name,
            anchors=tuple(anchors),
            path_steps=tuple(step.location for step in path.steps),
            defuse_found=len(found),
            extra_stubs=hops.stubs(parsed),
        )
        return build_path_slice(candidate, parsed, budget=budget, plan=plan)
