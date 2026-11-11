"""SARIF code flows to taint paths (E14-02).

Owning epic: E14. A ``codeFlow`` lists thread-flow locations in execution order. The first becomes
the ``source``, the last the ``sink`` and the rest ``propagator`` steps, or ``sanitiser`` where the
step's properties or kinds say so. An engine that reports sink first (``code_flow_order``) is
reversed here, because the model deliberately leaves that to the adapter.

``TaintPath`` has no upper bound on its length, so the ceiling ``MAX_CODE_FLOW_STEPS`` belongs to
this importer. Over-long flows lose their ``unimportant`` and deeply nested middle steps first and
are then trimmed from the middle; the source and the sink always survive. A note is the step's
message, truncated at a word boundary; ``region.snippet`` is never read.
"""

from pathlib import Path
from typing import Final

from codekavach.analysis.engines.base import CodeFlowOrder
from codekavach.analysis.engines.sarif.locations import (
    SourceCache,
    region_to_location,
    resolve_uri,
)
from codekavach.analysis.engines.sarif.model import CodeFlow, Run, ThreadFlowLocation
from codekavach.analysis.engines.sarif.textutil import clean_text
from codekavach.core.models.enums import TaintRole
from codekavach.core.models.location import Location
from codekavach.core.models.taint import MAX_NOTE_LENGTH, TaintPath, TaintStep

MAX_CODE_FLOW_STEPS: Final = 64
_IMPORTANCE: Final = {"unimportant": 0, "important": 1, "essential": 2}
_SANITISER_WORDS: Final = frozenset({"sanitiser", "sanitizer", "sanitise", "sanitize"})
_FUNCTION_KINDS: Final = frozenset({"function", "method", "member"})


def _symbol(step: ThreadFlowLocation) -> str | None:
    for logical in step.location.logical_locations if step.location else ():
        if logical.kind in _FUNCTION_KINDS and logical.name:
            return logical.name
    return None


def _is_sanitiser(step: ThreadFlowLocation) -> bool:
    if any(kind.lower() in _SANITISER_WORDS for kind in step.kinds):
        return True
    return any(
        bool(step.properties.get(name)) for name in ("sanitiser", "sanitizer", "isSanitizer")
    )


def _convert(
    step: ThreadFlowLocation, run: Run, root: Path, source: SourceCache
) -> tuple[Location, str | None] | None:
    physical = step.location.physical_location if step.location else None
    if physical is None or physical.artifact_location is None:
        return None
    path = resolve_uri(physical.artifact_location, run, root)
    if path is None:
        return None
    lines = source.lines(path)
    if lines is None:
        return None
    location: Location | None = None
    for symbol in (_symbol(step), None):
        try:
            location = region_to_location(
                physical.region, path, lines, column_kind=run.column_kind, symbol=symbol
            )
            break
        except ValueError:
            continue
    if location is None:
        return None
    message = step.location.message if step.location else None
    text = (message.text if message else None) or ""
    note = clean_text(text, MAX_NOTE_LENGTH) or None
    return location, note


def _trim(items: list[tuple[ThreadFlowLocation, Location, str | None]]) -> list[int]:
    """The indices to keep: the ends, then the most important and least nested middle steps."""
    total = len(items)
    if total <= MAX_CODE_FLOW_STEPS:
        return list(range(total))

    def keep_order(index: int) -> tuple[int, int, int]:
        step = items[index][0]
        importance = _IMPORTANCE.get((step.importance or "important").lower(), 1)
        nesting = step.nesting_level or 0
        return importance, -nesting, -min(index, total - 1 - index)

    middle = sorted(range(1, total - 1), key=keep_order, reverse=True)
    return sorted([0, total - 1, *middle[: MAX_CODE_FLOW_STEPS - 2]])


def code_flow_to_taint_path(
    flow: CodeFlow,
    run: Run,
    root: Path,
    source: SourceCache,
    *,
    order: CodeFlowOrder = "source_first",
) -> TaintPath | None:
    """The taint path of the first thread flow that yields a valid one, else ``None``."""
    for thread in flow.thread_flows:
        converted: list[tuple[ThreadFlowLocation, Location, str | None]] = []
        for step in thread.locations:
            pair = _convert(step, run, root, source)
            if pair is not None:
                converted.append((step, pair[0], pair[1]))
        if order == "sink_first":
            converted.reverse()
        if len(converted) < 2:
            continue
        keep = _trim(converted)
        steps: list[TaintStep] = []
        for position, index in enumerate(keep):
            flow_step, location, note = converted[index]
            if position == 0:
                role = TaintRole.SOURCE
            elif position == len(keep) - 1:
                role = TaintRole.SINK
            elif _is_sanitiser(flow_step):
                role = TaintRole.SANITISER
            else:
                role = TaintRole.PROPAGATOR
            steps.append(TaintStep(location=location, role=role, note=note))
        return TaintPath(steps=tuple(steps))
    return None
