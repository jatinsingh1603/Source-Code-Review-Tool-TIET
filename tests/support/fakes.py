"""Stand-ins for the pipeline facade and for backends, for CLI tests.

``StubOrchestrator`` has the keyword signature of ``run_scan()`` (E04-16): it records every call,
publishes a scripted list of events on the bus it is given, and returns a scripted outcome or
raises a scripted exception. ``fake_backend`` registers a fake for ``load_backend`` for one test.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli import backends
from codekavach.core.pipeline.events import Event, EventBus


@dataclass(frozen=True)
class FakeScanOutcome:
    """The attribute names of ``ScanOutcome`` (E04-16) with any values."""

    result: Any
    scan: Any
    state_dir: Path


@dataclass
class StubOrchestrator:
    """A scripted ``run_scan`` replacement."""

    events: Sequence[Event] = ()
    outcome: Any = None
    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, loaded: Any, target: str, **kwargs: Any) -> Any:
        self.calls.append({"loaded": loaded, "target": target, **kwargs})
        bus: EventBus | None = kwargs.get("bus")
        if bus is not None:
            for event in self.events:
                bus.publish(event)
        if self.error is not None:
            raise self.error
        return self.outcome


def fake_backend(monkeypatch: pytest.MonkeyPatch, dotted_path: str, obj: object) -> None:
    """Make ``load_backend`` return ``obj`` for ``dotted_path`` (``package.module.name``)."""
    module, _, attr = dotted_path.rpartition(".")
    monkeypatch.setitem(backends._OVERRIDES, (module, attr), obj)
