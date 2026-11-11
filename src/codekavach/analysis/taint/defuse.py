"""Reaching definitions and def-use chains over the lowered form (E17-01).

Owning epic: E17. A *definition* is a statement that writes a place (an ``Assign`` target, a
``Call`` result, a parameter at the entry, or a name an ``Unknown`` mentions). A *use* is a place
read by a statement. For each use, ``definitions`` returns the definitions that can reach it; for
each definition, ``uses`` returns the reads it can reach. The solver is a worklist over blocks in
reverse post-order, so a loop reaches its fixed point in a few rounds.

Rules: a write to a strong place (no ``[*]``, not truncated) replaces every definition of that
place and of every longer path below it (``a = x`` kills ``a.b``); a write to a weak place, or one
made by an ``Unknown``, adds a definition and kills nothing. A use of ``a.b`` is reached by
definitions of ``a.b``, of any prefix (``a``) and of any extension (``a.b.c``), because any of them
may have set the value. A ``Phi`` is recorded where two or more definitions of one place meet at a
join block; it is bookkeeping for the propagation pass and never part of a reader-facing path.
"""

from dataclasses import dataclass, field
from typing import Final

from codekavach.analysis.taint.cfg import CFG, build_cfg
from codekavach.analysis.taint.ir import (
    Assign,
    Branch,
    Call,
    Const,
    Expr,
    IRFunction,
    Phi,
    Place,
    Raise,
    Return,
    Stmt,
    Unknown,
)

PARAM_INDEX: Final = -1


@dataclass(frozen=True, slots=True)
class Site:
    """A statement position; ``index`` is ``PARAM_INDEX`` for a parameter at the entry."""

    block: int
    index: int


@dataclass(frozen=True, slots=True)
class Definition:
    """A write of ``place`` at ``site``; ``weak`` writes do not replace earlier ones."""

    site: Site
    place: Place
    weak: bool = False


@dataclass(frozen=True, slots=True)
class Use:
    """A read of ``place`` at ``site``."""

    site: Site
    place: Place


def places_in(expr: Expr | None) -> list[Place]:
    """Every place an expression reads, left to right."""
    if expr is None or isinstance(expr, Const):
        return []
    if isinstance(expr, Place):
        return [expr]
    if isinstance(expr, Unknown):
        return list(expr.mentions)
    found: list[Place] = []
    for operand in expr.operands:
        found.extend(places_in(operand))
    return found


def reads_of(stmt: Stmt) -> list[Place]:
    """The places a statement reads."""
    if isinstance(stmt, Assign):
        return places_in(stmt.value)
    if isinstance(stmt, Call):
        found = [stmt.receiver] if stmt.receiver is not None else []
        for arg in stmt.args:
            found.extend(places_in(arg))
        for _, value in stmt.kwargs:
            found.extend(places_in(value))
        return found
    if isinstance(stmt, Return | Raise):
        return places_in(stmt.value)
    if isinstance(stmt, Branch):
        return places_in(stmt.condition)
    if isinstance(stmt, Unknown):
        return list(stmt.mentions)
    return []


def writes_of(stmt: Stmt) -> list[tuple[Place, bool]]:
    """The places a statement writes, each with whether the write is weak."""
    if isinstance(stmt, Assign):
        return [(stmt.target, not stmt.target.strong())]
    if isinstance(stmt, Call):
        return [] if stmt.result is None else [(stmt.result, not stmt.result.strong())]
    if isinstance(stmt, Unknown):
        return [(place, True) for place in stmt.mentions]
    return []


def covers(written: Place, other: Place) -> bool:
    """Whether a strong write to ``written`` replaces ``other`` (equal or a longer path below)."""
    return written.base == other.base and other.steps[: len(written.steps)] == written.steps


@dataclass(slots=True)
class DefUse:
    """The result of the analysis of one function."""

    function: IRFunction
    cfg: CFG
    parameters: tuple[Definition, ...]
    phis: dict[int, tuple[Phi, ...]] = field(default_factory=dict)
    all_uses: list[Use] = field(default_factory=list)
    _reaching: dict[tuple[int, int, str], tuple[Definition, ...]] = field(default_factory=dict)
    _uses: dict[Definition, list[Use]] = field(default_factory=dict)

    def definitions(self, place: Place, block: int, index: int) -> tuple[Definition, ...]:
        """The definitions that reach the read of ``place`` by statement ``index`` of ``block``."""
        return self._reaching.get((block, index, place.text), ())

    def uses(self, definition: Definition) -> tuple[Use, ...]:
        """The reads that ``definition`` reaches, in the order they were found."""
        return tuple(self._uses.get(definition, ()))


State = dict[str, frozenset[Definition]]


def _step(state: State, definition: Definition) -> None:
    key = definition.place.text
    if definition.weak:
        state[key] = state.get(key, frozenset()) | {definition}
        return
    for name in list(state):
        remaining = frozenset(d for d in state[name] if not covers(definition.place, d.place))
        if remaining:
            state[name] = remaining
        else:
            del state[name]
    state[key] = frozenset({definition})


def _merge(states: list[State]) -> State:
    merged: State = {}
    for state in states:
        for key, defs in state.items():
            merged[key] = merged.get(key, frozenset()) | defs
    return merged


def analyse(function: IRFunction) -> DefUse:
    """Reaching definitions and def-use chains of ``function``."""
    cfg = build_cfg(function)
    blocks = {block.id: block for block in function.blocks}
    params = tuple(Definition(Site(0, PARAM_INDEX), Place(base=name)) for name in function.params)
    entry_state: State = {d.place.text: frozenset({d}) for d in params}
    out_state: dict[int, State] = {}
    in_state: dict[int, State] = {}

    pending = list(cfg.order)
    queued = set(pending)
    while pending:
        block_id = pending.pop(0)
        queued.discard(block_id)
        incoming = [out_state[p] for p in cfg.predecessors[block_id] if p in out_state]
        merged = _merge([entry_state, *incoming] if block_id == 0 else incoming)
        in_state[block_id] = merged
        current = dict(merged)
        for index, stmt in enumerate(blocks[block_id].stmts):
            for place, weak in writes_of(stmt):
                _step(current, Definition(Site(block_id, index), place, weak))
        if out_state.get(block_id) != current:
            out_state[block_id] = current
            for successor in cfg.successors[block_id]:
                if successor not in queued:
                    pending.append(successor)
                    queued.add(successor)

    info = DefUse(function=function, cfg=cfg, parameters=params)
    for block_id in cfg.order:
        state = dict(in_state.get(block_id, {}))
        for index, stmt in enumerate(blocks[block_id].stmts):
            site = Site(block_id, index)
            for place in reads_of(stmt):
                found = tuple(
                    sorted(
                        {d for defs in state.values() for d in defs if d.place.related(place)},
                        key=lambda d: (d.site.block, d.site.index, d.place.text),
                    )
                )
                info._reaching[(block_id, index, place.text)] = found
                use = Use(site, place)
                info.all_uses.append(use)
                for definition in found:
                    info._uses.setdefault(definition, []).append(use)
            for place, weak in writes_of(stmt):
                _step(state, Definition(site, place, weak))
    info.phis = _phis(cfg, in_state)
    return info


def _phis(cfg: CFG, in_state: dict[int, State]) -> dict[int, tuple[Phi, ...]]:
    found: dict[int, tuple[Phi, ...]] = {}
    for block_id in cfg.order:
        if len(cfg.predecessors[block_id]) < 2:
            continue
        phis = [
            Phi(
                place=min(defs, key=lambda d: (d.site.block, d.site.index)).place,
                block=block_id,
                sources=tuple(sorted({d.site.block for d in defs})),
            )
            for _, defs in sorted(in_state.get(block_id, {}).items())
            if len(defs) > 1
        ]
        if phis:
            found[block_id] = tuple(phis)
    return found
