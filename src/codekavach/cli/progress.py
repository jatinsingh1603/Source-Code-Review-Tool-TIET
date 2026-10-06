"""Live progress of a scan on stderr, rendered from the pipeline event bus (E05-11).

Owning epic: E05.

The orchestrator publishes typed events; this module is one subscriber. It draws a Rich display
on an interactive terminal, writes plain lines when stderr is piped or in CI, writes one JSON
object per line for tools, and stays silent under ``--quiet``. Stdout is never touched.

Progress output lands in terminals and in hosted CI logs, so every mode renders an explicit
allow-list of fields per event class. Only the event classes that the pipeline itself defines are
rendered: any other class, including a subclass that carries extra attributes, is ignored, and a
failed stage is reported by its policy and exception class name, never by exception text. Nothing
is sent anywhere.

Events arrive from stage threads (E04-19): handlers take a lock, do little and return. The
pipeline is not imported here, so that ``codekavach --version`` stays fast; events are recognised
by their defining module and their ``kind``.
"""

import json
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli.console import get_err_console
from codekavach.cli.prompts import is_interactive

if TYPE_CHECKING:
    from pydantic import JsonValue

    from codekavach.core.pipeline.events import (
        Event,
        EventBus,
        PlanResolved,
        ScanFinished,
        ScanStarted,
        StageFailed,
        StageFinished,
        StageProgress,
        StageStarted,
    )

PLAIN_PROGRESS_SECONDS: Final = 5.0
CACHED: Final = "cached"
EVENTS_MODULE: Final = "codekavach.core.pipeline.events"
SCAN_STARTED: Final = "scan.started"
PLAN_RESOLVED: Final = "plan.resolved"
STAGE_STARTED: Final = "stage.started"
STAGE_PROGRESS: Final = "stage.progress"
STAGE_FINISHED: Final = "stage.finished"
STAGE_FAILED: Final = "stage.failed"
SCAN_FINISHED: Final = "scan.finished"
SCAN_CANCELLED: Final = "scan.cancelled"


class ProgressMode(StrEnum):
    """Accepted values of ``--progress``."""

    auto = "auto"
    bar = "bar"
    plain = "plain"
    json = "json"
    off = "off"


class Renderer(Protocol):
    """One way of showing events."""

    def start(self) -> None:
        """Called in the main thread before the scan."""

    def stop(self) -> None:
        """Called in the main thread after the scan, also when it raised."""

    def handle(self, event: "Event") -> None:
        """Render one event; called from any thread."""


def resolve_mode(requested: ProgressMode, ctx: click.Context) -> ProgressMode:
    """The effective mode: ``auto`` becomes ``off``, ``bar`` or ``plain`` for this session.

    ``off`` under ``--quiet`` and under ``--json`` (tools opt in with ``--progress json``);
    ``bar`` when stderr is a terminal and the session is interactive; otherwise ``plain``.
    """
    if requested is not ProgressMode.auto:
        return requested
    from codekavach.cli.context import get_context  # noqa: PLC0415 - loads config models

    context = get_context(ctx)
    if context.quiet or context.json_mode:
        return ProgressMode.off
    return ProgressMode.bar if is_interactive(ctx) else ProgressMode.plain


def known_kind(event: object) -> str | None:
    """The ``kind`` of an event class defined by the pipeline itself, else ``None``.

    A class defined anywhere else, also a subclass of a pipeline event, is not rendered: it could
    carry attributes that the allow-lists below do not know.
    """
    if type(event).__module__ != EVENTS_MODULE:
        return None
    kind = getattr(type(event), "kind", None)
    return kind if isinstance(kind, str) else None


def _seconds(duration_ms: int) -> float:
    return duration_ms / 1000


def _finished_line(event: "StageFinished", separator: str) -> str:
    cached = " (cached)" if event.outcome == CACHED else ""
    return f"{separator}{_seconds(event.duration_ms):.1f}s{cached}"


def _write_stderr(line: str) -> None:
    sys.stderr.write(f"{line}\n")
    sys.stderr.flush()


class PlainRenderer:
    """One line per stage start and end, and at most one progress line per stage every 5 s."""

    def __init__(
        self,
        write: Callable[[str], None] = _write_stderr,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._write = write
        self._clock = clock
        self._lock = threading.Lock()
        self._last_progress: dict[str, float] = {}

    def start(self) -> None:
        """Nothing to prepare."""

    def stop(self) -> None:
        """Nothing to tear down."""

    def handle(self, event: "Event") -> None:
        """Write the line of ``event``, if its class has one."""
        kind = known_kind(event)
        with self._lock:
            if kind == STAGE_STARTED:
                self._write(f"[{cast('StageStarted', event).stage}] started")
            elif kind == STAGE_PROGRESS:
                self._progress(cast("StageProgress", event))
            elif kind == STAGE_FINISHED:
                finished = cast("StageFinished", event)
                self._last_progress.pop(finished.stage, None)
                self._write(f"[{finished.stage}] finished{_finished_line(finished, ' ')}")
            elif kind == STAGE_FAILED:
                failed = cast("StageFailed", event)
                self._last_progress.pop(failed.stage, None)
                self._write(f"stage {failed.stage} failed ({failed.policy})")

    def _progress(self, event: "StageProgress") -> None:
        now = self._clock()
        last = self._last_progress.get(event.stage)
        if last is not None and now - last < PLAIN_PROGRESS_SECONDS:
            return
        self._last_progress[event.stage] = now
        total = f"/{event.total}" if event.total is not None else ""
        self._write(f"[{event.stage}] {event.current}{total}")


def json_fields(event: "Event") -> "dict[str, JsonValue] | None":
    """The allow-listed fields of ``event`` for ``json`` mode; ``None`` for other classes."""
    kind = known_kind(event)
    fields: dict[str, JsonValue]
    if kind == SCAN_STARTED:
        fields = {"scan_id": event.scan_id, "total_stages": cast("ScanStarted", event).stage_count}
    elif kind == PLAN_RESOLVED:
        fields = {"order": list(cast("PlanResolved", event).stages)}
    elif kind == STAGE_STARTED:
        started = cast("StageStarted", event)
        fields = {"stage": started.stage, "index": started.index, "total": started.total}
    elif kind == STAGE_PROGRESS:
        progress = cast("StageProgress", event)
        fields = {"stage": progress.stage, "current": progress.current, "total": progress.total}
    elif kind == STAGE_FINISHED:
        finished = cast("StageFinished", event)
        fields = {
            "stage": finished.stage,
            "duration_s": _seconds(finished.duration_ms),
            "from_cache": finished.outcome == CACHED,
        }
    elif kind == STAGE_FAILED:
        failed = cast("StageFailed", event)
        fields = {"stage": failed.stage, "policy": failed.policy, "error_type": failed.error_type}
    elif kind == SCAN_FINISHED:
        ended = cast("ScanFinished", event)
        fields = {
            "scan_id": ended.scan_id,
            "duration_s": _seconds(ended.duration_ms),
            "finding_count": ended.findings_total,
        }
    elif kind == SCAN_CANCELLED:
        fields = {"scan_id": event.scan_id}
    else:
        return None
    return {"event": kind, **fields}


class JsonRenderer:
    """One compact JSON object per line for every listed event."""

    def __init__(self, write: Callable[[str], None] = _write_stderr) -> None:
        self._write = write
        self._lock = threading.Lock()

    def start(self) -> None:
        """Nothing to prepare."""

    def stop(self) -> None:
        """Nothing to tear down."""

    def handle(self, event: "Event") -> None:
        """Write the allow-listed fields of ``event`` as one line."""
        fields = json_fields(event)
        if fields is None:
            return
        line = json.dumps(fields, separators=(",", ":"))
        with self._lock:
            self._write(line)


class BarRenderer:
    """A Rich live display: one overall task and one task per running stage."""

    def __init__(self, console: Console) -> None:
        self.progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        self._lock = threading.Lock()
        self._overall: TaskID | None = None
        self._stages: dict[str, TaskID] = {}

    def start(self) -> None:
        """Start the live display (main thread)."""
        self.progress.start()

    def stop(self) -> None:
        """Stop the live display and restore the cursor (main thread)."""
        self.progress.stop()

    def handle(self, event: "Event") -> None:
        """Update the display for ``event``, if its class is shown."""
        kind = known_kind(event)
        with self._lock:
            if kind == SCAN_STARTED:
                total = cast("ScanStarted", event).stage_count
                self._overall = self.progress.add_task("scan", total=total)
            elif kind == STAGE_STARTED:
                self._stage_task(cast("StageStarted", event).stage)
            elif kind == STAGE_PROGRESS:
                progress = cast("StageProgress", event)
                self.progress.update(
                    self._stage_task(progress.stage),
                    completed=progress.current,
                    total=progress.total,
                )
            elif kind == STAGE_FINISHED:
                finished = cast("StageFinished", event)
                self._end_stage(finished.stage, f"{finished.stage}{_finished_line(finished, '  ')}")
            elif kind == STAGE_FAILED:
                failed = cast("StageFailed", event)
                self._end_stage(failed.stage, f"stage {failed.stage} failed ({failed.policy})")

    def stage_state(self, stage: str) -> tuple[float, float | None] | None:
        """``(completed, total)`` of the running task of ``stage``, or ``None``."""
        with self._lock:
            task_id = self._stages.get(stage)
            if task_id is None:
                return None
            task = self.progress.tasks[self.progress.task_ids.index(task_id)]
            return task.completed, task.total

    def _stage_task(self, stage: str) -> TaskID:
        if stage not in self._stages:
            self._stages[stage] = self.progress.add_task(stage, total=None)
        return self._stages[stage]

    def _end_stage(self, stage: str, line: str) -> None:
        task_id = self._stages.pop(stage, None)
        if task_id is not None:
            self.progress.remove_task(task_id)
        if self._overall is not None:
            self.progress.advance(self._overall)
        self.progress.console.print(line, markup=False, highlight=False)


def make_renderer(mode: ProgressMode, **options: Any) -> Renderer | None:
    """The renderer of a resolved mode; ``None`` for ``off``."""
    if mode is ProgressMode.bar:
        return BarRenderer(options.get("console") or get_err_console())
    if mode is ProgressMode.plain:
        return PlainRenderer(clock=options.get("clock") or time.monotonic)
    if mode is ProgressMode.json:
        return JsonRenderer()
    return None


@contextmanager
def progress_listener(
    ctx: click.Context,
    bus: "EventBus",
    mode: ProgressMode,
    *,
    clock: Callable[[], float] | None = None,
) -> Iterator[None]:
    """Show the events of ``bus`` while the block runs.

    Subscribes on entry; unsubscribes and stops the display on exit, also when the block raises
    (an exception, ``KeyboardInterrupt``), which restores the cursor.
    """
    renderer = make_renderer(resolve_mode(mode, ctx), clock=clock)
    if renderer is None:
        yield
        return
    renderer.start()
    unsubscribe = bus.subscribe(renderer.handle)
    try:
        yield
    finally:
        unsubscribe()
        renderer.stop()
