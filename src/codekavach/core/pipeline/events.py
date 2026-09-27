"""Typed pipeline events and a synchronous, thread-safe event bus.

Owning epic: E04.

Events leave the pipeline for terminals, CI logs and, later, browsers, so they are treated as an
egress-adjacent channel. The vocabulary is closed and has no free-text field: every string field
must match ``^[A-Za-z0-9_.:-]{1,64}$``, which excludes spaces, slashes, quotes and newlines, so a
path, a line of code or an exception message cannot be put into an event (supports I3). Consumers
map codes to human text.

Dispatch is synchronous in the publisher's thread; ``seq`` gives a total order per bus. Handlers
must only enqueue or update counters, because a slow handler slows the publishing stage. Events are
advisory: dropping every event must not change any artefact.
"""

import dataclasses
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

from pydantic import JsonValue

from codekavach.core.log import get_logger

TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
STAGE_OUTCOMES = frozenset({"succeeded", "cached"})

_log = get_logger("codekavach.pipeline.events")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _check(name: str, value: object) -> None:
    if value is None or isinstance(value, datetime):
        return
    if isinstance(value, bool):
        raise ValueError(f"event field {name!r} must not be a bool")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"event field {name!r} must not be negative")
        return
    if isinstance(value, str):
        if not TOKEN_PATTERN.match(value):
            raise ValueError(f"event field {name!r} must match {TOKEN_PATTERN.pattern}")
        return
    if isinstance(value, tuple):
        for item in value:
            if isinstance(item, tuple):
                raise ValueError(f"event field {name!r} must not nest tuples")
            _check(name, item)
        return
    raise ValueError(f"event field {name!r} has an unsupported type {type(value).__name__}")


@dataclass(frozen=True, slots=True, kw_only=True)
class Event:
    """Base class of pipeline events; subclasses add only token, count and tuple fields."""

    kind: ClassVar[str] = "event"

    scan_id: str
    at: datetime = field(default_factory=_utc_now)
    seq: int = 0

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("event field 'at' must be timezone-aware")
        for item in dataclasses.fields(self):
            _check(item.name, getattr(self, item.name))

    def to_dict(self) -> dict[str, JsonValue]:
        """A flat JSON-safe dict: ``event`` first, ``None`` fields omitted, tuples as lists."""
        result: dict[str, JsonValue] = {"event": self.kind}
        for item in dataclasses.fields(self):
            value = getattr(self, item.name)
            if value is None:
                continue
            if isinstance(value, datetime):
                text = value.astimezone(UTC).isoformat().replace("+00:00", "Z")
                result[item.name] = text
            elif isinstance(value, tuple):
                result[item.name] = list(value)
            else:
                result[item.name] = value
        return result


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanStarted(Event):
    """The scan began."""

    kind: ClassVar[str] = "scan.started"
    stage_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanResolved(Event):
    """The run plan is known: stage names in order and the size of each wave."""

    kind: ClassVar[str] = "plan.resolved"
    stages: tuple[str, ...]
    wave_sizes: tuple[int, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class StageStarted(Event):
    """A stage began."""

    kind: ClassVar[str] = "stage.started"
    stage: str
    index: int
    total: int


@dataclass(frozen=True, slots=True, kw_only=True)
class StageProgress(Event):
    """A stage processed ``current`` of ``total`` items of ``unit`` (a word such as files)."""

    kind: ClassVar[str] = "stage.progress"
    stage: str
    current: int
    total: int | None = None
    unit: str


@dataclass(frozen=True, slots=True, kw_only=True)
class StageFinished(Event):
    """A stage succeeded or was served from the cache."""

    kind: ClassVar[str] = "stage.finished"
    stage: str
    outcome: str
    duration_ms: int
    items_in: int | None = None
    items_out: int | None = None

    def __post_init__(self) -> None:
        Event.__post_init__(self)
        if self.outcome not in STAGE_OUTCOMES:
            raise ValueError("event field 'outcome' must be succeeded or cached")


@dataclass(frozen=True, slots=True, kw_only=True)
class StageFailed(Event):
    """A stage failed; ``error_type`` is an exception class name, never its message."""

    kind: ClassVar[str] = "stage.failed"
    stage: str
    policy: str
    error_code: str
    error_type: str
    duration_ms: int


@dataclass(frozen=True, slots=True, kw_only=True)
class StageSkipped(Event):
    """A stage did not run."""

    kind: ClassVar[str] = "stage.skipped"
    stage: str
    reason_code: str
    blocked_by: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ItemFailed(Event):
    """One item (candidate, file) of a stage failed; the item is named by an id."""

    kind: ClassVar[str] = "item.failed"
    stage: str
    item_id: str
    error_code: str


@dataclass(frozen=True, slots=True, kw_only=True)
class WarningRaised(Event):
    """A warning, as a machine code."""

    kind: ClassVar[str] = "warning"
    stage: str | None = None
    code: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanCancelled(Event):
    """The scan was cancelled (the token raises ``ScanCancelledError``)."""

    kind: ClassVar[str] = "scan.cancelled"
    stages_completed: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanFinished(Event):
    """The scan ended."""

    kind: ClassVar[str] = "scan.finished"
    status: str
    duration_ms: int
    findings_total: int | None = None


EVENT_TYPES: Mapping[str, type[Event]] = MappingProxyType(
    {
        cls.kind: cls
        for cls in (
            ScanStarted,
            PlanResolved,
            StageStarted,
            StageProgress,
            StageFinished,
            StageFailed,
            StageSkipped,
            ItemFailed,
            WarningRaised,
            ScanCancelled,
            ScanFinished,
        )
    }
)

Handler = Callable[[Event], None]


class EventBus(Protocol):
    """Where the orchestrator publishes events."""

    def publish(self, event: Event) -> None:
        """Deliver ``event`` to every subscriber."""

    def subscribe(self, handler: Handler) -> Callable[[], None]:
        """Add ``handler``; the returned function removes it (idempotent)."""


class NullEventBus:
    """Drops every event."""

    def publish(self, event: Event) -> None:
        """Do nothing."""

    def subscribe(self, handler: Handler) -> Callable[[], None]:
        """Accept and ignore ``handler``."""
        return lambda: None


class InMemoryEventBus:
    """Numbers events 1, 2, 3 ... and calls handlers synchronously in subscription order."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handlers: list[Handler] = []
        self._seq = 0

    def publish(self, event: Event) -> None:
        """Assign the next ``seq`` and deliver; a failing handler is logged and skipped."""
        with self._lock:
            self._seq += 1
            numbered = dataclasses.replace(event, seq=self._seq)
            handlers = tuple(self._handlers)
        for handler in handlers:
            try:
                handler(numbered)
            except Exception as error:  # noqa: BLE001 - handlers must not break the scan
                _log.warning(
                    "event_handler_failed",
                    event_kind=numbered.kind,
                    error_type=type(error).__name__,
                )

    def subscribe(self, handler: Handler) -> Callable[[], None]:
        """Add ``handler``; the returned function removes it once."""
        entry: list[Any] = [handler]
        with self._lock:
            self._handlers.append(handler)

        def unsubscribe() -> None:
            with self._lock:
                if entry and entry[0] in self._handlers:
                    self._handlers.remove(entry.pop())

        return unsubscribe
