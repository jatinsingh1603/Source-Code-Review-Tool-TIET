"""From a flow witness to a ``TaintPath`` (E17-02).

Owning epic: E17. The path built here has three very different readers, and each constrains it:

* the **slicer** (M1) keeps exactly the statements on the path, so a step that is not needed is
  code disclosed for nothing;
* the **report** prints the steps as a numbered trace, so every step needs a location a reader can
  open;
* the **SARIF renderer** (E31) writes the path back out as a ``codeFlow`` with
  ``threadFlowLocations`` in execution order, the inverse of what E14-02 does for external
  engines. Steps are therefore always in execution order, source first, and never sink first.

Trimming is a privacy control as much as a performance one. A longer path is a larger slice and
more disclosure, so a path over ``taint.max_path_steps`` keeps its source, its sink, every
sanitiser step and the most recent propagators, and the candidate is marked
``taint.path_trimmed``. When a sink has more paths than ``taint.max_paths_per_sink`` the shortest
are kept, for the same reason.

Step notes name an operation and a symbol (``concat``, ``cursor.execute arg 0``), never the value
being built. A path that cannot satisfy the ``TaintPath`` validators is dropped with a log entry.
"""

from dataclasses import dataclass
from typing import Final

from pydantic import ValidationError

from codekavach.analysis.taint.ir import MODULE_FUNCTION, IRFunction
from codekavach.analysis.taint.propagate import FlowWitness
from codekavach.analysis.taint.state import Step
from codekavach.core.log import get_logger
from codekavach.core.models import Location, TaintPath, TaintRole, TaintStep
from codekavach.core.models.taint import MAX_NOTE_LENGTH

MAX_SYMBOL: Final = 512
_log = get_logger("codekavach.analysis.taint.path")


@dataclass(frozen=True, slots=True)
class PathResult:
    """A built path and whether it was trimmed to fit the step cap."""

    path: TaintPath
    trimmed: bool


def enclosing_symbol(function: IRFunction) -> str | None:
    """The symbol recorded on every step: the qualified function name, none for the module."""
    if function.qualname == MODULE_FUNCTION or len(function.qualname) > MAX_SYMBOL:
        return None
    return function.qualname


def _located(location: Location, symbol: str | None) -> Location:
    return location if symbol is None else location.model_copy(update={"symbol": symbol})


def _sink_note(witness: FlowWitness) -> str:
    where = "any arg" if witness.arg_index is None else f"arg {witness.arg_index}"
    return f"{witness.sink_callee[:120]} {where}"


def _sanitiser_note(step: Step, witness: FlowWitness) -> str:
    covered = ",".join(sorted(step.covers)) or "none"
    note = f"{step.note or 'sanitiser'}; covers={covered}"
    required = witness.sink.context
    if required is not None and required not in step.covers:
        note += f"; sanitiser.inadequate required_context={required} covered={covered}"
    return note


def _taint_step(step: Step, witness: FlowWitness, symbol: str | None) -> TaintStep:
    if step.role is TaintRole.SANITISER:
        note: str | None = _sanitiser_note(step, witness)
    else:
        note = step.note
    return TaintStep(
        location=_located(step.location, symbol),
        role=step.role,
        note=None if note is None else note[:MAX_NOTE_LENGTH],
    )


def _steps(witness: FlowWitness, symbol: str | None) -> list[TaintStep]:
    steps = [_taint_step(step, witness, symbol) for step in witness.steps]
    steps.append(
        TaintStep(
            location=_located(witness.sink_location, symbol),
            role=TaintRole.SINK,
            note=_sink_note(witness)[:MAX_NOTE_LENGTH],
        )
    )
    return steps


def _trim(steps: list[TaintStep], limit: int) -> list[TaintStep]:
    """Source, sink, every sanitiser and the most recent propagators, in execution order."""
    if len(steps) <= limit:
        return steps
    sanitisers = [i for i, s in enumerate(steps) if s.role is TaintRole.SANITISER]
    keep = {0, len(steps) - 1}
    room = limit - len(keep)
    keep.update(sanitisers[-room:] if room > 0 else [])
    room = limit - len(keep)
    for index in range(len(steps) - 2, 0, -1):
        if room <= 0:
            break
        if index not in keep:
            keep.add(index)
            room -= 1
    return [steps[i] for i in sorted(keep)]


def build_path_result(
    witness: FlowWitness, function: IRFunction, max_steps: int = 64
) -> PathResult | None:
    """The path of ``witness`` with its trimming flag, or ``None`` when it is not a valid path."""
    steps = _steps(witness, enclosing_symbol(function))
    trimmed = _trim(steps, max_steps)
    try:
        return PathResult(TaintPath(steps=tuple(trimmed)), len(trimmed) < len(steps))
    except (ValidationError, ValueError):
        _log.warning("taint_path_invalid", steps=len(steps))
        return None


def build_path(witness: FlowWitness, function: IRFunction, max_steps: int = 64) -> TaintPath | None:
    """The ``TaintPath`` of ``witness`` in execution order, or ``None`` when it is not valid."""
    result = build_path_result(witness, function, max_steps)
    return None if result is None else result.path


def cap_per_sink(witnesses: list[FlowWitness], limit: int) -> list[FlowWitness]:
    """At most ``limit`` witnesses per sink call, the shortest first, in a deterministic order."""
    grouped: dict[tuple[int, int, str], list[FlowWitness]] = {}
    for witness in witnesses:
        key = (
            witness.sink_location.start_line,
            witness.sink_location.start_col or 0,
            witness.sink.entry.id,
        )
        grouped.setdefault(key, []).append(witness)
    kept: list[FlowWitness] = []
    for key in sorted(grouped, key=lambda item: item):
        kept.extend(sorted(grouped[key], key=lambda flow: flow.sort_key)[:limit])
    return kept
