"""The intraprocedural backward slice strategy (E11-03).

Owning epic: E11.

From the statement of the candidate (the sink) the strategy walks def-use chains backwards inside
the function: the statements that define what the sink reads, then the statements that define what
those read, and so on, collecting each defining statement together with its control ancestors. It
needs no taint engine: a location is enough.

**Termination.** Each statement is expanded once, so a loop-carried dependence (a cycle in the
def-use graph) ends the walk; and a depth cap (``privacy.slice.defuse_depth``, default 20) bounds
it. The walk is breadth-first, so a statement is found at its shortest distance from the sink, and
that distance is its rank. The predecessors found beyond the cap are counted in the slice's
``recall`` record (found, not included), so the evaluation can see what the cap cost.

When the sink is not inside a function there is no chain to walk (``no_function``).
"""

from codekavach.core.models import Candidate, CodeSlice, Location, SliceStrategy
from codekavach.privacy.slicing.base import NotApplicableError, SlicingError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.pathslice import Anchor, PathPlan, build_path_slice
from codekavach.privacy.slicing.stubs import StubStats

DEFAULT_DEPTH = 20


def _path_steps(candidate: Candidate) -> tuple[Location, ...]:
    path = candidate.taint_path
    return () if path is None else tuple(step.location for step in path.steps)


class BackwardSliceStrategy:
    """Cuts the statements the sink depends on, and what controls them."""

    name = SliceStrategy.BACKWARD_SLICE

    def __init__(self, *, depth: int = DEFAULT_DEPTH) -> None:
        self._depth = depth

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``; ``NotApplicableError`` outside a function."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs."""
        sink = candidate.locations[0]
        excluded, reason = parsed.is_excluded(sink.path)
        if excluded:
            raise SlicingError(reason)
        if not parsed.has_parsed(sink.path):
            raise SlicingError("unsupported_language")
        flow = parsed.defuse_of(sink.path).flow_for(sink)
        start = None if flow is None else flow.statement_at(sink.start_line)
        if flow is None or start is None:
            raise NotApplicableError("no_function")
        found: dict[int, int] = {}
        expanded = {start}
        queue = [(start, 0)]
        while queue:
            current, depth = queue.pop(0)
            within = sink if current == start else None
            for key in flow.reads_of(current, within=within):
                for definition in flow.reaching(current, key):
                    if definition == start:
                        continue
                    if definition not in found or depth + 1 < found[definition]:
                        found[definition] = depth + 1
                    if definition not in expanded:
                        expanded.add(definition)
                        queue.append((definition, depth + 1))
        anchors = tuple(
            Anchor(flow.location_of(index), depth, "defuse")
            for index, depth in sorted(found.items())
            if depth <= self._depth
        )
        plan = PathPlan(
            strategy=self.name,
            anchors=anchors,
            path_steps=_path_steps(candidate),
            defuse_found=len(found),
            truncated=len(anchors) < len(found),
        )
        return build_path_slice(candidate, parsed, budget=budget, plan=plan)
