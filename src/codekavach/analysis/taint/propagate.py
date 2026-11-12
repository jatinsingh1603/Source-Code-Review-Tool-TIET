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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from codekavach.analysis.rules.pack import Catalogue, CatalogueEntry
from codekavach.analysis.taint.catalogue import UNKNOWN_SOURCE, Binding, SinkMatch
from codekavach.analysis.taint.cfg import build_cfg
from codekavach.analysis.taint.defuse import places_in
from codekavach.analysis.taint.ir import (
    ANY_INDEX,
    Assign,
    Branch,
    Call,
    Const,
    Expr,
    IRFunction,
    Op,
    Place,
    Raise,
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

if TYPE_CHECKING:
    from codekavach.analysis.taint.summary import FunctionSummary

CLOCK_EVERY: Final = 64
MAX_DEPTH: Final = 5  # the default of taint.max_depth
ANY_CONTEXT: Final = "*"
VALIDATORS: Final = frozenset({"includes", "has", "contains", "__contains__"})
PARAM_PREFIX: Final = "param:"
REQUEST_SEED: Final = "framework.request@"
MUTATORS: Final = frozenset(
    {"append", "add", "extend", "update", "insert", "push", "unshift", "setdefault", "appendleft",
     "put", "set"}
)  # fmt: skip
SummaryLookup = Callable[[Call], "FunctionSummary | None"]
# A seeded parameter: (origin key, label, note). The origin key is completed with the location.
Seed = tuple[str, str, str]


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
    depth: int = 0
    sink_symbol: str | None = None

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
    seen: set[tuple[str, str, int | str]] = field(default_factory=set)
    seeds: Mapping[str, Seed] = field(default_factory=dict)
    lookup: SummaryLookup | None = None
    returns: Facts = field(default_factory=dict)
    block_unknown: bool = False
    max_depth: int = MAX_DEPTH
    validators: dict[str, frozenset[str]] = field(default_factory=dict)


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
    seeds: Mapping[str, Seed] | None = None,
    lookup: SummaryLookup | None = None,
    block_unknown: bool = False,
) -> list[FlowWitness]:
    """``propagate`` with the catalogues already bound (the stage binds once per file).

    ``observe`` receives the settled state after each block (the explain dump uses it).
    ``seeds`` taints the named parameters at entry, ``lookup`` supplies callee summaries.
    """
    return analyse(
        function,
        binding,
        budget=budget,
        settings=settings,
        observe=observe,
        seeds=seeds,
        lookup=lookup,
        block_unknown=block_unknown,
    ).flows


@dataclass(slots=True)
class Analysis:
    """The flows of one function and the facts of the values it returns."""

    flows: list[FlowWitness]
    returns: Facts
    exit_state: TaintState = field(default_factory=TaintState)


def analyse(
    function: IRFunction,
    binding: Binding,
    *,
    budget: Budget,
    settings: TaintSettings | None = None,
    observe: Callable[[dict[int, TaintState]], None] | None = None,
    seeds: Mapping[str, Seed] | None = None,
    lookup: SummaryLookup | None = None,
    block_unknown: bool = False,
) -> Analysis:
    """Propagate through ``function``; the building block of summaries and of the stage."""
    if not function.blocks:
        return Analysis([], {}, TaintState())
    run = _Run(function, binding, settings or TaintSettings(), budget)
    run.max_depth = run.settings.max_depth
    run.seeds = seeds or {}
    run.lookup = lookup
    run.block_unknown = block_unknown
    states = _solve(run)
    if observe is not None:
        observe(states)
    flows = sorted(run.flows, key=lambda flow: (flow.sink_location.start_line, flow.sort_key))
    exit_state = TaintState()
    for settled in states.values():
        exit_state = exit_state.join(settled)
    return Analysis(flows, run.returns, exit_state)


def _initial_state(run: _Run) -> TaintState:
    """The entry state: every seeded parameter holds one fact with its own origin."""
    state = TaintState()
    location = run.function.location
    for name, (key, label, note) in run.seeds.items():
        origin = f"{key}@{location.start_line}:{location.start_col}"
        step = Step(
            TaintRole.SOURCE,
            location.model_copy(update={"symbol": run.function.qualname}),
            note[:120],
            symbol=run.function.qualname,
        )
        fact = Fact(value=Tainted(frozenset({label})), chain=(step,))
        state.write(Place(base=name), {origin: fact})
    return state


def _solve(run: _Run) -> dict[int, TaintState]:
    cfg = build_cfg(run.function)
    blocks = {block.id: block for block in run.function.blocks}
    passes = 1 + (run.settings.loop_iterations if cfg.back_edges else 0)
    out: dict[int, TaintState] = {}
    ins: dict[int, TaintState] = {}
    initial = _initial_state(run) if run.seeds else None
    entry = cfg.order[0] if cfg.order else None
    for _ in range(passes):
        changed = False
        for block_id in cfg.order:
            run.budget.check()
            state = _incoming(cfg.predecessors[block_id], out)
            if initial is not None and block_id == entry:
                state = state.join(initial)
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
        if initial is not None and block_id == entry:
            state = state.join(initial)
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
        if record and stmt.value is not None:
            location = stmt.location or run.function.location
            run.returns = merge(run.returns, _eval(run, stmt.value, location, state))


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
        validated = _validated(run, stmt, state)
        if validated and _bails_out(run, stmt):
            state.clear_origins(validated, frozenset({ANY_CONTEXT}))


def _validated(run: _Run, stmt: Branch, state: TaintState) -> frozenset[str]:
    """Origins an allow-list test in the condition vouches for (``x in ALLOWED``, ``.includes``)."""
    found: set[str] = set()
    for place in places_in(stmt.condition):
        found.update(run.validators.get(place.text, ()))
    for node in _compares(stmt.condition):
        listed = any(isinstance(o, Place) and o.base.isupper() for o in node.operands)
        if listed:
            for operand in node.operands:
                if isinstance(operand, Place) and not operand.base.isupper():
                    found.update(state.read(operand))
    return frozenset(found)


def _compares(expr: Expr) -> list[Op]:
    if not isinstance(expr, Op):
        return []
    here = [expr] if expr.style == "compare" else []
    return here + [node for operand in expr.operands for node in _compares(operand)]


def _bails_out(run: _Run, stmt: Branch) -> bool:
    """Whether one arm of the branch only raises or returns a constant (a rejection)."""
    blocks = {block.id: block for block in run.function.blocks}
    for target in (stmt.then_block, stmt.else_block):
        block = blocks.get(target)
        if block is None or not block.stmts or len(block.stmts) > 4:
            continue
        last = block.stmts[-1]
        if isinstance(last, Raise):
            return True
        if isinstance(last, Return) and (last.value is None or isinstance(last.value, Const)):
            return True
    return False


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
        # the catalogue names this exact request value: it replaces the whole-request seed
        facts = {o: f for o, f in facts.items() if not o.startswith(REQUEST_SEED)}
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
    if method in VALIDATORS and call.result is not None:
        tested = frozenset().union(*(facts.keys() for facts in args))
        if tested:
            run.validators[call.result.text] = tested
    if record:
        _record(run, call, args, kwargs)
    result: Facts
    summary = run.lookup(call) if run.lookup is not None and source is None else None
    if source is not None:
        result = _source_fact(source, call.location, name)
    elif summary is not None:
        result = _apply_summary(run, call, summary, args, kwargs, state, record=record)
    else:
        _mutate_receiver(run, call, method, args, kwargs, state)
        inputs = merge(receiver, *args, *(facts for _, facts in kwargs))
        result = _result(run, call, method, inputs)
    if call.result is not None:
        state.write(call.result, result)


def _mutate_receiver(  # noqa: PLR0917
    run: _Run,
    call: Call,
    method: str,
    args: list[Facts],
    kwargs: list[tuple[str, Facts]],
    state: TaintState,
) -> None:
    """A container mutator (``append``, ``add``...) stores its arguments in the receiver."""
    if method not in MUTATORS or call.receiver is None:
        return
    stored = merge(*args, *(facts for _, facts in kwargs))
    if not stored:
        return
    stepped = with_step(stored, Step(TaintRole.PROPAGATOR, call.location, f"store {method}"))
    state.write(call.receiver.extend(ANY_INDEX, run.settings.max_access_path), stepped)


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
    if run.block_unknown:  # taint.unknown_callee = block: an unmodelled callee returns clean data
        return {}
    return with_step(
        inputs, Step(TaintRole.PROPAGATOR, where, f"call {method}"[:120]), uncertain=True
    )


def _apply_summary(  # noqa: PLR0917
    run: _Run,
    call: Call,
    summary: "FunctionSummary",
    args: list[Facts],
    kwargs: list[tuple[str, Facts]],
    state: TaintState,
    *,
    record: bool,
) -> Facts:
    """The result facts of a call to a function with a summary, and the flows it reaches."""
    method = last_segment(call.callee.text.removeprefix("new "))
    # a bound method call does not pass the receiver as an argument: its parameter 0 is the receiver
    bound = (
        bool(summary.params)
        and summary.params[0] in {"self", "cls", "this"}
        and "." in (call.callee.text)
    )
    offset = 1 if bound else 0
    by_index: dict[int, Facts] = {i + offset: facts for i, facts in enumerate(args)}
    for key, facts in kwargs:
        if key in summary.params:
            by_index[summary.params.index(key)] = facts
    caller = run.function.qualname
    note = f"call {method}"[:120]
    if record:
        for reach in summary.param_to_sink:
            facts = by_index.get(reach.param, {})
            if not facts or reach.depth + 1 > run.max_depth:
                continue
            for origin, fact in sorted(facts.items()):
                if reach.sink.context is not None and (
                    reach.sink.context in fact.cleared or ANY_CONTEXT in fact.cleared
                ):
                    continue
                seen_key = (
                    origin,
                    f"{call.location.start_line}:{call.location.start_col}",
                    reach.key,
                )
                if seen_key in run.seen:
                    continue
                run.seen.add(seen_key)
                crossing = Step(TaintRole.PROPAGATOR, call.location, f"{note} arg {reach.param}")
                steps = (*fact.chain, crossing, *reach.steps)
                run.flows.append(
                    FlowWitness(
                        origin=origin,
                        label=sorted(fact.labels)[0] if fact.labels else UNKNOWN_SOURCE,
                        source_id=origin.split("@", 1)[0],
                        steps=steps,
                        sink=reach.sink,
                        sink_location=reach.location,
                        sink_callee=reach.callee,
                        arg_index=reach.arg_index,
                        uncertain=fact.uncertain or reach.uncertain,
                        guards=fact.guards,
                        covered=frozenset().union(*(st.covers for st in steps)),
                        depth=reach.depth + 1,
                        sink_symbol=reach.symbol,
                    )
                )
    result: Facts = {}
    for index in sorted(summary.param_to_return):
        facts = by_index.get(index, {})
        if not facts:
            continue
        stepped = with_step(
            facts,
            Step(TaintRole.PROPAGATOR, call.location, note),
            uncertain=summary.degraded,
        )
        cleared = frozenset(ctx for i, ctx in summary.sanitises if i == index)
        result = merge(result, with_cleared(stepped, cleared) if cleared else stepped)
    for label in sorted(summary.source_to_return):
        origin = f"summary.{label}@{call.location.start_line}:{call.location.start_col}"
        step = Step(TaintRole.SOURCE, call.location, f"source via {method}"[:120])
        result = merge(result, {origin: Fact(Tainted(frozenset({label})), (step,))})
    del caller
    _apply_param_to_param(run, call, summary, by_index, offset, state, note)
    return result


def _apply_param_to_param(  # noqa: PLR0917 - the pieces of one call site
    run: _Run,
    call: Call,
    summary: "FunctionSummary",
    by_index: dict[int, Facts],
    offset: int,
    state: TaintState,
    note: str,
) -> None:
    """A callee that stores one argument into another taints the argument expression's place."""
    for source_index, target_index in sorted(summary.param_to_param):
        facts = by_index.get(source_index, {})
        position = target_index - offset
        if not facts or not 0 <= position < len(call.args):
            continue
        target = call.args[position]
        if isinstance(target, Place):
            stepped = with_step(
                facts,
                Step(TaintRole.PROPAGATOR, call.location, f"{note} stores arg {source_index}"),
                uncertain=summary.degraded,
            )
            state.write(target.extend(ANY_INDEX, run.settings.max_access_path), stepped)


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
            if sink.context is not None and (
                sink.context in fact.cleared or ANY_CONTEXT in fact.cleared
            ):
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
