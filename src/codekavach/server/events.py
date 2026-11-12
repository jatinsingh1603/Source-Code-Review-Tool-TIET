"""Per-scan progress events for the server-sent event stream.

Owning epic: E32.

The job runner turns pipeline events (E04-05, token fields only) into the dashboard's event types
``stage``, ``progress``, ``log``, ``finding``, ``egress`` and ``done`` and appends them to an
``EventLog`` (each stamped with ``at``, an ISO 8601 UTC time):
in memory for live readers and as NDJSON in the scan's workspace so a finished scan can be replayed
after a restart. Every event has a monotonic ``id`` so a client resumes with ``Last-Event-ID``
without repeats or gaps. Messages are built from codes and counts, never from source text.
"""

import asyncio
import json
import threading
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

EVENT_FILE: Final = "events.ndjson"
EVENT_TYPES: Final = frozenset({"stage", "progress", "log", "finding", "egress", "done"})
HEARTBEAT_SECONDS: Final = 15.0
POLL_SECONDS: Final = 0.25


@dataclass(frozen=True)
class StreamEvent:
    """One event of a scan's stream."""

    id: int
    type: str
    data: dict[str, Any]

    def frame(self) -> str:
        """The SSE frame of this event."""
        payload = json.dumps(self.data, separators=(",", ":"), default=str)
        return f"id: {self.id}\nevent: {self.type}\ndata: {payload}\n\n"


class EventLog:
    """The append-only event list of one scan, mirrored to ``events.ndjson``."""

    def __init__(self, path: Path | None) -> None:
        self._lock = threading.Lock()
        self._events: list[StreamEvent] = []
        self._path = path
        self.closed = False
        if path is not None and path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                    self._events.append(StreamEvent(item["id"], item["type"], item["data"]))
                except (ValueError, KeyError, TypeError):
                    continue
            self.closed = any(event.type == "done" for event in self._events)

    def append(self, kind: str, data: dict[str, Any]) -> StreamEvent:
        """Add an event of type ``kind`` (one of ``EVENT_TYPES``)."""
        if kind not in EVENT_TYPES:
            raise ValueError(f"unknown event type {kind!r}")
        stamped = {"at": datetime.now(UTC).isoformat(), **data}
        if kind == "stage":
            # Every stage event carries its item counts; null when the stage reports none.
            stamped.setdefault("count", None)
            stamped.setdefault("total", None)
        with self._lock:
            event = StreamEvent(len(self._events) + 1, kind, stamped)
            self._events.append(event)
            if kind == "done":
                self.closed = True
            if self._path is not None:
                line = json.dumps(
                    {"id": event.id, "type": kind, "data": stamped}, separators=(",", ":"),
                    default=str,
                )  # fmt: skip
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        return event

    def since(self, last_id: int) -> list[StreamEvent]:
        """Events with an id above ``last_id``."""
        with self._lock:
            return self._events[last_id:] if last_id >= 0 else list(self._events)

    def all(self) -> list[StreamEvent]:
        """Every event so far."""
        return self.since(0)


class EventHub:
    """The event logs of every scan this process knows, opened on demand."""

    def __init__(self, scans_dir: Path) -> None:
        self._scans_dir = scans_dir
        self._lock = threading.Lock()
        self._logs: dict[str, EventLog] = {}

    def log(self, scan_id: str) -> EventLog:
        """The log of ``scan_id`` (loaded from its NDJSON file the first time)."""
        with self._lock:
            found = self._logs.get(scan_id)
            if found is None:
                directory = self._scans_dir / scan_id
                path = directory / EVENT_FILE if directory.is_dir() else None
                found = EventLog(path)
                self._logs[scan_id] = found
            return found

    def forget(self, scan_id: str) -> None:
        """Drop the in-memory log of a deleted scan."""
        with self._lock:
            self._logs.pop(scan_id, None)


async def stream(
    log: EventLog,
    *,
    last_id: int,
    is_disconnected: Callable[[], Any],
    heartbeat: float = HEARTBEAT_SECONDS,
) -> AsyncIterator[str]:
    """SSE frames of ``log`` after ``last_id`` until ``done`` or the client goes away."""
    cursor = last_id
    idle = 0.0
    yield "retry: 2000\n\n"
    while True:
        events = log.since(cursor)
        for event in events:
            cursor = event.id
            yield event.frame()
            if event.type == "done":
                return
        if events:
            idle = 0.0
        elif log.closed:
            return
        if await is_disconnected():
            return
        await asyncio.sleep(POLL_SECONDS)
        idle += POLL_SECONDS
        if idle >= heartbeat:
            idle = 0.0
            yield ": keep-alive\n\n"
