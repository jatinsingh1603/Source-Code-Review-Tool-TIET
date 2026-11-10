"""Choosing the richest strategy whose inputs exist, and saying why a weaker one was used (E11-03).

Owning epic: E11.

``StrategySelector`` tries, in this order, the taint-path slice (needs a ``TaintPath``), the
backward slice (needs the sink inside a function), the enclosing function and the sink window, and
returns the first slice that can be made. It never falls back silently: the slice it returns
records the strategy that built it (``strategy``) and, when a richer one was skipped, the first
reason it was (``fallback_reason``: ``no_taint_path``, ``no_function``, ``over_budget``, ...). A
slice built by the window because no path was available is a materially weaker input, and the
report's methodology can then state how many findings were triaged on a path slice versus a
window (docs/research/INSIGHTS.md section 8.1).

A refusal for a reason that no other strategy can cure (a never-send, vendored, generated or
minified file, an unsupported language) is raised at once: a smaller window of a file the policy
does not send is still a file the policy does not send.

``privacy.slice.default_strategy`` is the richest strategy the project allows; the default,
``enclosing_function``, never starts with a path. A hotspot candidate is cut for discovery by
``HotspotStrategy`` and has no chain.
"""

from typing import Protocol

from codekavach.config import Settings
from codekavach.core.models import Candidate, CandidateKind, CodeSlice, SliceStrategy
from codekavach.privacy.slicing.base import NotApplicableError, SlicingError
from codekavach.privacy.slicing.budget import SliceBudget
from codekavach.privacy.slicing.index import ParseIndex
from codekavach.privacy.slicing.strategies.backward import BackwardSliceStrategy
from codekavach.privacy.slicing.strategies.enclosing import EnclosingFunctionStrategy
from codekavach.privacy.slicing.strategies.hotspot import HotspotStrategy
from codekavach.privacy.slicing.strategies.taintpath import TaintPathStrategy
from codekavach.privacy.slicing.strategies.window import SinkWindowStrategy
from codekavach.privacy.slicing.stubs import StubStats

CHAIN = (
    SliceStrategy.TAINT_PATH,
    SliceStrategy.BACKWARD_SLICE,
    SliceStrategy.ENCLOSING_FUNCTION,
    SliceStrategy.SINK_WINDOW,
)
# Refusals a weaker strategy may cure; any other reason ends the attempt.
_CURABLE = frozenset({"over_budget", "not_coherent", "no_enclosing_code"})


class _Strategy(Protocol):
    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]: ...


class StrategySelector:
    """Builds the slice of a candidate with the richest strategy that has its inputs."""

    def __init__(
        self,
        *,
        ceiling: SliceStrategy = SliceStrategy.TAINT_PATH,
        defuse_depth: int = 20,
        callee_depth: int = 1,
    ) -> None:
        if ceiling not in CHAIN:
            raise ValueError(f"{ceiling.value} is not a strategy the selector can start from")
        self._chain = CHAIN[CHAIN.index(ceiling) :]
        self._strategies: dict[SliceStrategy, _Strategy] = {
            SliceStrategy.TAINT_PATH: TaintPathStrategy(callee_depth=callee_depth),
            SliceStrategy.BACKWARD_SLICE: BackwardSliceStrategy(depth=defuse_depth),
            SliceStrategy.ENCLOSING_FUNCTION: EnclosingFunctionStrategy(),
            SliceStrategy.SINK_WINDOW: SinkWindowStrategy(),
        }

    @classmethod
    def from_settings(cls, settings: Settings) -> "StrategySelector":
        """A selector configured by ``privacy.slice`` of ``settings``."""
        section = settings.privacy.slice
        return cls(
            ceiling=SliceStrategy(section.default_strategy),
            defuse_depth=section.defuse_depth,
            callee_depth=section.callee_depth,
        )

    def build(self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget) -> CodeSlice:
        """The slice for ``candidate``; ``SlicingError`` when no strategy can make one."""
        return self.build_with_stats(candidate, parsed, budget=budget)[0]

    def build_with_stats(
        self, candidate: Candidate, parsed: ParseIndex, *, budget: SliceBudget
    ) -> tuple[CodeSlice, StubStats]:
        """``build`` and the statistics of the stubs."""
        if candidate.kind is CandidateKind.HOTSPOT:
            return HotspotStrategy().build_with_stats(candidate, parsed, budget=budget)
        skipped: str | None = None
        failure: SlicingError | None = None
        for name in self._chain:
            try:
                slice_, stats = self._strategies[name].build_with_stats(
                    candidate, parsed, budget=budget
                )
            except NotApplicableError as unavailable:
                skipped = skipped or unavailable.fallback
                failure = unavailable
                continue
            except SlicingError as refused:
                if refused.reason not in _CURABLE:
                    raise
                skipped = skipped or refused.reason
                failure = refused
                continue
            if skipped is not None and slice_.fallback_reason is None:
                slice_ = slice_.model_copy(update={"fallback_reason": skipped})
            return slice_, stats
        assert failure is not None  # noqa: S101 - the chain is never empty
        raise failure
