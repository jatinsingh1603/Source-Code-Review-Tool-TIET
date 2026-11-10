"""The forward slice strategy (E11-03).

Owning epic: E11.

From a source expression the strategy walks def-use chains forwards: the statements that read what
the source statement defines, then the statements that read what those define, and so on. It serves
the discovery task (what does this value reach?) and the evaluation harness, which compares the
statements a forward slice reaches with the path a taint engine found (slice recall).

The source is the first step of the candidate's ``TaintPath`` when it has one, else the candidate's
own location. The candidate's own statement is always in the slice and is protected, as in every
path strategy, so a forward slice that does not reach it still shows it. Termination and the depth
cap are the same as for the backward slice: each statement is expanded once, breadth-first, up to
``privacy.slice.defuse_depth`` steps; what lies beyond is counted as found, not included.
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


class ForwardSliceStrategy:
    """Cuts the statements a source value reaches, and what controls them."""

    name = SliceStrategy.FORWARD_SLICE

    def __init__(self, *, depth: int = DEFAULT_DEPTH) -> None:
        self._depth = depth

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``; ``NotApplicableError`` when the source is in no function."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs."""
        primary = candidate.locations[0]
        excluded, reason = parsed.is_excluded(primary.path)
        if excluded:
            raise SlicingError(reason)
        source = candidate.taint_path.source.location if candidate.taint_path else primary
        if parsed.is_excluded(source.path)[0] or not parsed.has_parsed(source.path):
            raise NotApplicableError("unresolved_path")
        flow = parsed.defuse_of(source.path).flow_for(source)
        start = None if flow is None else flow.statement_at(source.start_line)
        if flow is None or start is None:
            raise NotApplicableError("no_function")
        found: dict[int, int] = {}
        expanded = {start}
        queue = [(start, 0)]
        while queue:
            current, depth = queue.pop(0)
            for key in flow.writes_of(current):
                for reader in flow.readers(current, key):
                    if reader == start:
                        continue
                    if reader not in found or depth + 1 < found[reader]:
                        found[reader] = depth + 1
                    if reader not in expanded:
                        expanded.add(reader)
                        queue.append((reader, depth + 1))
        anchors = [Anchor(source, 0, "step")]
        anchors.extend(
            Anchor(flow.location_of(index), depth, "defuse")
            for index, depth in sorted(found.items())
            if depth <= self._depth
        )
        plan = PathPlan(
            strategy=self.name,
            anchors=tuple(anchors),
            path_steps=_path_steps(candidate),
            defuse_found=len(found),
            truncated=len(anchors) - 1 < len(found),
        )
        return build_path_slice(candidate, parsed, budget=budget, plan=plan)
