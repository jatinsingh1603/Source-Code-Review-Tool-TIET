"""The sink-window slice strategy (E11-03).

Owning epic: E11.

The cheapest path-free strategy and the last resort of the selector: it needs nothing but a
location. For each location of the candidate it takes the statements within ``N`` lines before and
``M`` lines after, snapped to whole statements (a statement that touches the window is taken
whole), together with the compound statements around them, the guards before them and the
signature of their function, like every path strategy. ``N`` comes from the budget and the number
of locations, ``M`` is half of it (the context before a sink, its guards and definitions, explains
it more than what follows).

Code outside any function is cut as the top-level statements that touch the window. Rank is the
distance in lines from the candidate's location, so an over-budget window loses its edges first.
"""

from codekavach.core.models import Candidate, CodeSlice, Location, SliceStrategy
from codekavach.privacy.slicing.base import SlicingError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.pathslice import Anchor, PathPlan, build_path_slice
from codekavach.privacy.slicing.shape import SUPPORTED, span
from codekavach.privacy.slicing.stubs import StubStats

_MIN_WINDOW = 3
_MAX_WINDOW = 30
_TOKENS_PER_WINDOW_LINE = 64
_LOCATION_STRIDE = 1000


def window_size(budget: SliceBudget, locations: int) -> tuple[int, int]:
    """``(lines before, lines after)`` for ``locations`` locations under ``budget``."""
    before = max(
        _MIN_WINDOW,
        min(_MAX_WINDOW, budget.max_tokens // (_TOKENS_PER_WINDOW_LINE * max(locations, 1))),
    )
    return before, max(2, before // 2)


def _distance(first: int, last: int, location: Location) -> int:
    if last < location.start_line:
        return location.start_line - last
    if first > location.end_line:
        return first - location.end_line
    return 0


class SinkWindowStrategy:
    """Cuts the statements around each location of the candidate."""

    name = SliceStrategy.SINK_WINDOW

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``, or ``SlicingError`` with the reason it cannot be made."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs."""
        primary = candidate.locations[0]
        excluded, reason = parsed.is_excluded(primary.path)
        if excluded:
            raise SlicingError(reason)
        usable = [
            location
            for location in candidate.locations
            if not parsed.is_excluded(location.path)[0] and parsed.has_parsed(location.path)
        ]
        before, after = window_size(budget, len(usable))
        anchors: list[Anchor] = []
        for number, location in enumerate(usable):
            low, high = max(1, location.start_line - before), location.end_line + after
            offset = number * _LOCATION_STRIDE
            flow = parsed.defuse_of(location.path).flow_for(location)
            if flow is not None:
                for statement in flow.statements[1:]:
                    lines = statement.lines
                    if lines.end >= low and lines.start <= high:
                        rank = offset + _distance(lines.start, lines.end, location)
                        anchors.append(Anchor(flow.location_of(statement.index), rank, "step"))
                continue
            file = parsed.parsed_of(location.path)
            if file.tree is None or file.language not in SUPPORTED:
                continue
            for node in file.tree.root_node.named_children:
                lines = span(node)
                if node.type != "comment" and lines.end >= low and lines.start <= high:
                    rank = offset + _distance(lines.start, lines.end, location)
                    where = Location(path=location.path, start_line=lines.start, end_line=lines.end)
                    anchors.append(Anchor(where, rank, "step"))
        path = candidate.taint_path
        steps = () if path is None else tuple(step.location for step in path.steps)
        plan = PathPlan(strategy=self.name, anchors=tuple(anchors), path_steps=steps)
        return build_path_slice(candidate, parsed, budget=budget, plan=plan)
