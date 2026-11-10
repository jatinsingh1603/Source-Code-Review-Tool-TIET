"""Crossing function boundaries along a taint path, up to a depth (E11-03).

Owning epic: E11.

A taint path may run through several functions: the source is read in one, passed to a second and
reaches the sink in a third. Each extra function is a *disclosure decision*, not only a cost
(docs/research/INSIGHTS.md section 1.2: demand-driven exploration asks for each one), so the
helper that every path strategy shares counts function hops from the candidate's own function and
cuts code only up to ``callee_depth`` hops (``privacy.slice.callee_depth``, default 1). A function
beyond the cap is not cut: it becomes a signature stub (E11-02) with the reason
``out_of_slice_callee``, and the model may ask for its body through the context loop (E11-04).

Hops are counted along the path from the sink back to the source, by distinct function: the
candidate's function is hop 0, the next function met is hop 1, and so on. A step that sits in an
excluded file (never-send, vendored, generated) is dropped, with no stub: the stub builder reports
excluded callees by count only.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from codekavach.core.models import StubReason, TaintStep
from codekavach.core.models.slice import Stub
from codekavach.parsing.functions import FunctionRange
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.stubs import function_stub


@dataclass(frozen=True, slots=True)
class PathHops:
    """The steps of a path split by how far their function is from the candidate's."""

    near: tuple[TaintStep, ...]
    far: tuple[tuple[str, FunctionRange], ...]
    dropped: int

    def stubs(self, parsed: ParseIndex) -> tuple[Stub, ...]:
        """The signature stubs of the functions beyond the cap, in path order."""
        found: list[Stub] = []
        for path, function in self.far:
            stub = function_stub(parsed, path, function, StubReason.OUT_OF_SLICE_CALLEE)
            if stub is not None:
                found.append(stub)
        return tuple(found)


def partition_by_depth(parsed: ParseIndex, steps: Sequence[TaintStep], depth: int) -> PathHops:
    """Split ``steps`` (source first, sink last) into code within ``depth`` hops and the rest."""
    order: dict[tuple[str, int | None], int] = {}
    near: list[TaintStep] = []
    far: dict[tuple[str, int], tuple[str, FunctionRange]] = {}
    dropped = 0
    for step in reversed(steps):
        path = step.location.path
        if parsed.is_excluded(path)[0] or not parsed.has_parsed(path):
            dropped += 1
            continue
        function = parsed.enclosing_function(step.location)
        key = (path, None if function is None else function.full.start_line)
        hop = order.setdefault(key, len(order))
        if hop <= depth or function is None:
            near.append(step)
        else:
            far.setdefault((path, function.full.start_line), (path, function))
    near.reverse()
    return PathHops(tuple(near), tuple(far.values()), dropped)
