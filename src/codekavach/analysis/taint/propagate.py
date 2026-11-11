"""Intraprocedural taint propagation over a lowered function (E17-02).

Owning epic: E17. ``propagate`` walks the blocks of a function in reverse post-order, applies a
transfer function per statement and, for a function with loops, repeats the walk up to
``taint.loop_iterations`` more times or until nothing changes. A final pass over the settled
in-states records the flows, so a flow is reported once, with the facts of the fixed point.

Transfer functions:

* ``Assign`` copies the facts of the right-hand side to the target place. String operations,
  arithmetic and collections carry the taint of their operands; a comparison does not.
* ``Call``: a source call makes its result tainted with the source's kind; a sanitiser clears the
  contexts it declares to cover (and records a ``sanitiser`` step either way); a narrowing
  conversion clears ``sql`` and ``shell``; string and container-read methods carry taint certainly;
  any other callee with a tainted argument returns ``Unknown`` (E17-03 replaces that with
  summaries). A sink with a tainted argument at its argument index records a flow.
* ``Branch`` does not refine taint (version 1.0 has no path conditions): it records the line of
  the guard on every fact it tests, which the slicer can include and the reviewer can judge.

Evaluation is lazy in the sense that matters: nothing is computed for a place no source taints.
The flows are raw client data (invariant I2): they hold locations and symbols and are read only by
``path.py`` and the stage.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from codekavach.analysis.rules.pack import Catalogue, CatalogueEntry
from codekavach.analysis.taint.catalogue import UNKNOWN_SOURCE, Binding, SinkMatch
from codekavach.analysis.taint.cfg import build_cfg
from codekavach.analysis.taint.defuse import places_in
from codekavach.analysis.taint.ir import (
    Assign,
    Branch,
    Call,
    Const,
    Expr,
    IRFunction,
    Op,
    Place,
    Return,
    Stmt,
    Unknown,
)
from codekavach.analysis.taint.state import (
    Fact,
    Facts,
    Step,
    Tainted,
    TaintState,
    merge,
    with_cleared,
    with_step,
)
from codekavach.analysis.taint.strings import (
    NARROWING,
    READ_METHODS,
    STRING_METHODS,
    last_segment,
    operation_of,
)
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Location, TaintRole

CLOCK_EVERY: Final = 64


class BudgetExceededError(Exception):
    """The time budget of one function ran out."""


@dataclass(slots=True)
class Budget:
    """A wall-clock allowance for one function."""

    deadline: float
    _ticks: int = 0

    @classmethod
    def of(cls, seconds: float) -> "Budget":
        """A budget of ``seconds`` starting now."""
        return cls(time.monotonic() + seconds)

    def check(self) -> None:
        """Raise ``BudgetExceededError`` when the allowance is spent (the clock is read rarely)."""
        self._ticks += 1
        if self._ticks % CLOCK_EVERY == 0 and time.monotonic() > self.deadline:
            raise BudgetExceededError


@dataclass(frozen=True, slots=True)
class FlowWitness:
    """One source-to-sink flow: the chain of steps before the sink, and the sink itself."""

    origin: str
    label: str
    source_id: str
    steps: tuple[Step, ...]
    sink: SinkMatch
    sink_location: Location
    sink_callee: str
    arg_index: int | None
    uncertain: bool
    guards: tuple[int, ...] = ()
    covered: frozenset[str] = frozenset()

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """Shortest first, then by position, then by origin: the deterministic trimming order."""
        return (len(self.steps), self.sink_location.start_line, self.origin)


@dataclass(slots=True)
class _Run:
    function: IRFunction
    binding: Binding
    settings: TaintSettings
    budget: Budget
    flows: list[FlowWitness] = field(default_factory=list)
    seen: set[tuple[str, str, int]] = field(default_factory=set)


def propagate(
    function: IRFunction,
    catalogues: tuple[Catalogue, ...] | list[Catalogue],
    *,
    budget: Budget,
    settings: TaintSettings | None = None,
    aliases: tuple[tuple[str, str], ...] = (),
    language: str = "python",
) -> list[FlowWitness]:
    """Every source-to-sink flow of ``function``, in a deterministic order.

    Raises ``BudgetExceededError`` when ``budget`` runs out; the caller reports the function as a
    ``taint_timeout`` item failure and goes on.
    """
    binding = Binding(catalogues, aliases, language)
    return propagate_bound(function, binding, budget=budget, settings=settings)


def propagate_bound(
    function: IRFunction,
    binding: Binding,
    *,
    budget: Budget,
    settings: TaintSettings | None = None,
    observe: Callable[[dict[int, TaintState]], None] | None = None,
) -> list[FlowWitness]:
    """``propagate`` with the catalogues already bound (the stage binds once per file).

    ``observe`` receives the settled state after each block (the explain dump uses it).
    """
    if not function.blocks:
        return []
    run = _Run(function, binding, settings or TaintSettings(), budget)
    states = _solve(run)
    if observe is not None:
        observe(states)
    return sorted(run.flows, key=lambda flow: (flow.sink_location.start_line, flow.sort_key))


def _solve(run: _Run) -> dict[int, TaintState]:
    cfg = build_cfg(run.function)
    blocks = {block.id: block for block in run.function.blocks}
    passes = 1 + (run.settings.loop_iterations if cfg.back_edges else 0)
    out: dict[int, TaintState] = {}
    ins: dict[int, TaintState] = {}
    for _ in range(passes):
        changed = False
        for block_id in cfg.order:
            run.budget.check()
            state = _incoming(cfg.predecessors[block_id], out)
            ins[block_id] = state.copy()
            for stmt in blocks[block_id].stmts:
                _transfer(run, stmt, state, record=False)
            if out.get(block_id) != state:
                out[block_id] = state
                changed = True
        if not changed:
            break
    for block_id in cfg.order:
        state = _incoming(cfg.predecessors[block_id], out)
        for stmt in blocks[block_id].stmts:
            _transfer(run, stmt, state, record=True)
    return out


def _incoming(predecessors: tuple[int, ...], out: dict[int, TaintState]) -> TaintState:
    state = TaintState()
    for pred in predecessors:
        if pred in out:
            state = state.join(out[pred])
    return state


# --- transfer functions ----------------------------------------------------------------------


def _transfer(run: _Run, stmt: Stmt, state: TaintState, *, record: bool) -> None:
    run.budget.check()
    if isinstance(stmt, Assign):
        facts = _eval(run, stmt.value, stmt.location, state)
        if facts:
            facts = with_step(facts, Step(TaintRole.PROPAGATOR, stmt.location, _note(stmt.value)))
        state.write(stmt.target, facts)
    elif isinstance(stmt, Call):
        _call(run, stmt, state, record=record)
    elif isinstance(stmt, Branch):
        _guard(run, stmt, state)
    elif isinstance(stmt, Unknown):
        _unknown(run, stmt, state)
    elif isinstance(stmt, Return):
        return


def _note(value: Expr) -> str:
    """The operation name of an assignment's right-hand side: no literal, no variable value."""
    if isinstance(value, Op):
        return operation_of(value) or "compute"
    return "assign"


def _guard(run: _Run, stmt: Branch, state: TaintState) -> None:
    line = stmt.location.start_line if stmt.location is not None else 0
    if line <= 0:
        return
    origins: set[str] = set()
    for place in places_in(stmt.condition):
        origins.update(state.read(place))
    if origins:
        state.guard(origins, line)


def _unknown(run: _Run, stmt: Unknown, state: TaintState) -> None:
    """An unmodelled statement may define and use everything it mentions."""
    if stmt.location is None:
        return
    gathered = merge(*(state.read(place) for place in stmt.mentions)) if stmt.mentions else {}
    if not gathered:
        return
    step = Step(TaintRole.PROPAGATOR, stmt.location, "unmodelled")
    uncertain = with_step(gathered, step, uncertain=True)
    for place in stmt.mentions:
        state.write(place.model_copy(update={"truncated": True}), uncertain)


def _eval(run: _Run, expr: Expr, location: Location, state: TaintState) -> Facts:
    """The facts of an expression evaluated at ``location``."""
    if isinstance(expr, Const):
        return {}
    if isinstance(expr, Place):
        return _read(run, expr, location, state)
    if isinstance(expr, Unknown):
        gathered = merge(*(_read(run, place, location, state) for place in expr.mentions))
        if not gathered:
            return {}
        return with_step(
            gathered, Step(TaintRole.PROPAGATOR, location, "unmodelled"), uncertain=True
        )
    if operation_of(expr) is None:  # a comparison yields a boolean
        return {}
    return merge(*(_eval(run, operand, location, state) for operand in expr.operands))


def _read(run: _Run, place: Place, location: Location, state: TaintState) -> Facts:
    facts = state.read(place)
    entry = run.binding.source_for_place(place)
    if entry is not None:
        facts = merge(facts, _source_fact(entry, location, place.text))
    return facts


def _source_fact(entry: CatalogueEntry, location: Location, text: str) -> Facts:
    label = entry.type or UNKNOWN_SOURCE
    origin = f"{entry.id}@{location.start_line}:{location.start_col}"
    note = f"source {text}" if text else "source"
    step = Step(TaintRole.SOURCE, location, note[:120])
    return {origin: Fact(value=Tainted(frozenset({label})), chain=(step,))}


def _call(run: _Run, call: Call, state: TaintState, *, record: bool) -> None:
    binding = run.binding
    name = call.callee.text.removeprefix("new ")
    method = last_segment(name)
    source = binding.source_for_call(call)
    args = [_eval(run, arg, call.location, state) for arg in call.args]
    kwargs = [(key, _eval(run, value, call.location, state)) for key, value in call.kwargs]
    receiver = _read(run, call.receiver, call.location, state) if call.receiver is not None else {}
    if record:
        _record(run, call, args, kwargs)
    result: Facts
    if source is not None:
        result = _source_fact(source, call.location, name)
    else:
        inputs = merge(receiver, *args, *(facts for _, facts in kwargs))
        result = _result(run, call, method, inputs)
    if call.result is not None:
        state.write(call.result, result)


def _result(run: _Run, call: Call, method: str, inputs: Facts) -> Facts:
    """The facts of a call's result given the facts of its receiver and arguments."""
    if not inputs:
        return {}
    where = call.location
    sanitiser = run.binding.sanitiser_for(call)
    if sanitiser is not None:
        covers = frozenset(sanitiser.covers)
        note = f"sanitiser {method}"
        return with_step(inputs, Step(TaintRole.SANITISER, where, note[:120], covers))
    bare = call.receiver is None and (
        call.callee.symbol is None or call.callee.symbol.startswith(("builtins.", "globalThis."))
    )
    narrowing = NARROWING.get(method) if bare else None
    if narrowing is not None:
        stepped = with_step(inputs, Step(TaintRole.PROPAGATOR, where, f"narrowing {method}"))
        return with_cleared(stepped, narrowing.clears)
    operation = STRING_METHODS.get(method)
    if operation is None and call.receiver is not None:
        operation = READ_METHODS.get(method)
    if operation is not None:
        return with_step(inputs, Step(TaintRole.PROPAGATOR, where, f"{operation} {method}"[:120]))
    return with_step(
        inputs, Step(TaintRole.PROPAGATOR, where, f"call {method}"[:120]), uncertain=True
    )


def _record(run: _Run, call: Call, args: list[Facts], kwargs: list[tuple[str, Facts]]) -> None:
    sink = run.binding.sink_for(call)
    if sink is None:
        return
    if sink.arg is not None:
        wanted = [(sink.arg, args[sink.arg])] if sink.arg < len(args) else []
    else:
        wanted = [(index, facts) for index, facts in enumerate(args)]
        wanted.extend((-1, facts) for _, facts in kwargs)
    for index, facts in wanted:
        for origin, fact in sorted(facts.items()):
            if sink.context is not None and sink.context in fact.cleared:
                continue
            key = (origin, f"{call.location.start_line}:{call.location.start_col}", index)
            if key in run.seen:
                continue
            run.seen.add(key)
            run.flows.append(_flow(origin, fact, sink, call, index))


def _flow(origin: str, fact: Fact, sink: SinkMatch, call: Call, index: int) -> FlowWitness:
    covered: frozenset[str] = frozenset()
    for step in fact.chain:
        covered |= step.covers
    label = sorted(fact.labels)[0] if fact.labels else UNKNOWN_SOURCE
    return FlowWitness(
        origin=origin,
        label=label,
        source_id=origin.split("@", 1)[0],
        steps=fact.chain,
        sink=sink,
        sink_location=call.location,
        sink_callee=call.callee.text[:200],
        arg_index=None if index < 0 else index,
        uncertain=fact.uncertain,
        guards=fact.guards,
        covered=covered,
    )
