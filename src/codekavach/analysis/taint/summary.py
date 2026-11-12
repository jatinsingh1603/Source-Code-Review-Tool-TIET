"""Function summaries for interprocedural taint (E17-03).

Owning epic: E17. A summary is what a caller needs to know about a callee without reading its
body again: which parameters reach its return value (``param_to_return``), which reach a sink
inside it or below it (``param_to_sink``), which source kinds it returns on its own
(``source_to_return``), which contexts it sanitises on the way (``sanitises``) and whether the
answer is a widened guess (``degraded``). ``compute_summary`` seeds every parameter with its own
origin (``param:<index>``) and runs the ordinary propagation of ``propagate.py`` once, so a
summary is exactly as precise as the intraprocedural engine and inherits its sanitiser and
narrowing model. ``param_to_param`` (a callee storing one argument into another, by writing
below the parameter or through a container mutator) is read from the exit state of the same run.
"""

from dataclasses import dataclass, replace
from typing import Final

from codekavach.analysis.taint.catalogue import Binding, SinkMatch
from codekavach.analysis.taint.ir import IRFunction
from codekavach.analysis.taint.propagate import (
    PARAM_PREFIX,
    Budget,
    FlowWitness,
    Seed,
    SummaryLookup,
    analyse,
)
from codekavach.analysis.taint.state import Step
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Location

SUMMARY_VERSION: Final = "1"
SKIPPED_PARAMS: Final = frozenset({"self", "cls"})
MAX_REACHES: Final = 32


@dataclass(frozen=True, slots=True)
class SinkReach:
    """Parameter ``param`` reaches ``sink`` at ``location``, ``depth`` calls below the callee."""

    param: int
    sink: SinkMatch
    location: Location
    callee: str
    arg_index: int | None
    steps: tuple[Step, ...]
    uncertain: bool = False
    depth: int = 0
    symbol: str | None = None

    @property
    def key(self) -> str:
        """Identity of the sink occurrence, used to deduplicate paths to the same sink."""
        loc = self.location
        return f"{self.sink.entry.id}@{loc.path}:{loc.start_line}:{loc.start_col}"


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """What a call to ``symbol`` does with taint."""

    symbol: str
    params: tuple[str, ...] = ()
    version: str = SUMMARY_VERSION
    param_to_return: frozenset[int] = frozenset()
    param_to_sink: tuple[SinkReach, ...] = ()
    source_to_return: frozenset[str] = frozenset()
    param_to_param: frozenset[tuple[int, int]] = frozenset()
    sanitises: tuple[tuple[int, str], ...] = ()
    degraded: bool = False
    reason: str | None = None

    def signature(self) -> tuple[object, ...]:
        """The parts a fixed-point iteration compares: relations, not the chains inside them."""
        return (
            self.param_to_return,
            tuple(sorted((r.param, r.key) for r in self.param_to_sink)),
            self.source_to_return,
            self.param_to_param,
            self.sanitises,
            self.degraded,
        )

    def widened(self, reason: str) -> "FunctionSummary":
        """Any tainted parameter taints the return value; marked degraded with its reason."""
        every = frozenset(range(len(self.params)))
        return replace(self, param_to_return=every, degraded=True, reason=reason)


def _restamp(steps: tuple[Step, ...], symbol: str) -> tuple[Step, ...]:
    return tuple(replace(step, symbol=step.symbol or symbol) for step in steps)


def _reach_of(flow: FlowWitness, function: IRFunction) -> SinkReach | None:
    index = flow.origin[len(PARAM_PREFIX) : flow.origin.index("@")]
    if not index.isdigit():
        return None
    return SinkReach(
        param=int(index),
        sink=flow.sink,
        location=flow.sink_location,
        callee=flow.sink_callee,
        arg_index=flow.arg_index,
        steps=_restamp(flow.steps[1:], function.qualname),  # the first step is the seed
        uncertain=flow.uncertain,
        depth=flow.depth,
        symbol=flow.sink_symbol or function.qualname,
    )


def compute_summary(  # noqa: PLR0912
    function: IRFunction,
    binding: Binding,
    *,
    settings: TaintSettings,
    lookup: SummaryLookup | None,
    block_unknown: bool = False,
    key: str | None = None,
) -> FunctionSummary:
    """The summary of ``function``, from one propagation with every parameter seeded."""
    symbol = key or function.qualname
    if not function.is_analysed:
        return FunctionSummary(symbol, function.params, degraded=True, reason="function skipped")
    seeds: dict[str, Seed] = {
        name: (f"{PARAM_PREFIX}{index}", "param", f"parameter {name}")
        for index, name in enumerate(function.params)
        if name not in SKIPPED_PARAMS
    }
    if not seeds:
        analysis = analyse(
            function,
            binding,
            budget=Budget.of(settings.timeout_seconds),
            settings=settings,
            lookup=lookup,
            block_unknown=block_unknown,
        )
    else:
        analysis = analyse(
            function,
            binding,
            budget=Budget.of(settings.timeout_seconds),
            settings=settings,
            seeds=seeds,
            lookup=lookup,
            block_unknown=block_unknown,
        )
    best: dict[tuple[int, str], SinkReach] = {}
    for flow in analysis.flows:
        if not flow.origin.startswith(PARAM_PREFIX):
            continue
        reach = _reach_of(flow, function)
        if reach is None:
            continue
        slot = (reach.param, reach.key)
        if slot not in best or len(reach.steps) < len(best[slot].steps):
            best[slot] = reach
    to_return: set[int] = set()
    sources: set[str] = set()
    sanitises: set[tuple[int, str]] = set()
    for origin, fact in analysis.returns.items():
        if origin.startswith(PARAM_PREFIX):
            index = int(origin[len(PARAM_PREFIX) : origin.index("@")])
            to_return.add(index)
            sanitises.update((index, ctx) for ctx in fact.cleared)
        else:
            sources.update(label for label in fact.labels if label != "param")
    reaches = tuple(sorted(best.values(), key=lambda r: (r.param, r.key)))[:MAX_REACHES]
    stores: set[tuple[int, int]] = set()
    for stored, facts in analysis.exit_state.entries.values():
        target = function.params.index(stored.base) if stored.base in function.params else -1
        if target < 0 or not stored.steps or stored.base in SKIPPED_PARAMS:
            continue  # only a write below a parameter is visible to the caller
        for origin in facts:
            if origin.startswith(PARAM_PREFIX):
                source = int(origin[len(PARAM_PREFIX) : origin.index("@")])
                if source != target:
                    stores.add((source, target))
    return FunctionSummary(
        symbol=symbol,
        params=function.params,
        param_to_return=frozenset(to_return),
        param_to_sink=reaches,
        source_to_return=frozenset(sources),
        param_to_param=frozenset(stores),
        sanitises=tuple(sorted(sanitises)),
    )
