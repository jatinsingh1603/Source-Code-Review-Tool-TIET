"""Shared test kit for the pipeline: a configurable fake stage, a ready ``RunContext``, a recording
event bus and fake plugin distributions discoverable through ``importlib.metadata``.

Nothing under ``src/`` may import this module.
"""

import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path

from codekavach.config import Settings
from codekavach.core.models.ids import new_scan_id
from codekavach.core.pipeline.budget import Budget
from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.events import Event, EventBus, InMemoryEventBus
from codekavach.core.pipeline.keys import is_multi_provider
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import StageCategory, StageInfo
from codekavach.core.store.base import ArtefactStore
from codekavach.core.store.memory import InMemoryArtefactStore

FIXED_SCAN_ID = "scan_00000000000000000000000000"
FIXED_SALT_HEX = "00" * 32
SLEEP_SLICE_SECONDS = 0.01


class CollectingBus(InMemoryEventBus):
    """An event bus that also records every published (numbered) event."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[Event] = []
        self.subscribe(self.events.append)

    def kinds(self) -> list[str]:
        """The ``kind`` of every recorded event, in order."""
        return [event.kind for event in self.events]

    def of(self, kind: str) -> list[Event]:
        """The recorded events of one kind."""
        return [event for event in self.events if event.kind == kind]


class FakeStage:
    """A stage whose reads, writes, delay and failure are configured by its constructor."""

    def __init__(
        self,
        name: str,
        *,
        requires: Iterable[str] = (),
        provides: Iterable[str] = (),
        optional_requires: Iterable[str] = (),
        category: StageCategory | None = None,
        version: str = "1",
        writes: Mapping[str, object] | None = None,
        parts: Mapping[str, object] | None = None,
        raises: BaseException | None = None,
        sleep_seconds: float = 0.0,
        write_before_raise: bool = True,
        cooperative: bool = True,
        **metadata: object,
    ) -> None:
        self.name = name
        self.requires = frozenset(requires)
        self.provides = frozenset(provides)
        self.optional_requires = frozenset(optional_requires)
        self.category = category
        self.version = version
        self._writes = writes
        self._parts = dict(parts or {})
        self._raises = raises
        self._sleep_seconds = sleep_seconds
        self._write_before_raise = write_before_raise
        self._cooperative = cooperative
        self._lock = threading.Lock()
        self.calls = 0
        self.seen: dict[str, object] = {}
        for key, value in metadata.items():
            setattr(self, key, value)

    def _sleep(self, ctx: RunContext) -> None:
        deadline = time.monotonic() + self._sleep_seconds
        while (left := deadline - time.monotonic()) > 0:
            time.sleep(min(SLEEP_SLICE_SECONDS, left))
            if self._cooperative:
                ctx.check_cancelled()

    def run(self, ctx: RunContext) -> None:
        """Read the present required keys, optionally sleep, write, then optionally raise."""
        with self._lock:
            self.calls += 1
        for key in sorted(self.requires):
            if not ctx.artefacts.has(key):
                continue
            if is_multi_provider(key):
                ref = ctx.artefacts.ref(key)
                self.seen[key] = [part for part, _ in ref.parts] if ref else []
            else:
                self.seen[key] = ctx.artefacts.get_json(key)
        if self._sleep_seconds > 0:
            self._sleep(ctx)
        if self._raises is not None and not self._write_before_raise:
            raise self._raises
        writes = self._writes
        if writes is None:
            writes = {key: {"by": self.name} for key in sorted(self.provides - self._parts.keys())}
        for key, value in writes.items():
            ctx.artefacts.put(key, value)
        for key, value in self._parts.items():
            ctx.artefacts.put_part(key, self.name, value)
        if self._raises is not None:
            raise self._raises


def make_run_context(
    *,
    store: ArtefactStore | None = None,
    bus: EventBus | None = None,
    salt: ScanSalt | None = None,
    settings: Settings | None = None,
    project_root: Path | None = None,
    state_dir: Path | None = None,
    budget: Budget | None = None,
    scan_id: str | None = None,
    random_scan_id: bool = False,
) -> RunContext:
    """A ``RunContext`` with deterministic defaults.

    The default salt is all zeros: it is for tests only and must never be used for a real scan.
    """
    return RunContext(
        scan_id=scan_id or (new_scan_id() if random_scan_id else FIXED_SCAN_ID),
        config=settings or Settings(),
        artefacts=store if store is not None else InMemoryArtefactStore(),
        events=bus if bus is not None else CollectingBus(),
        cancellation=CancellationToken(),
        budget=budget or Budget(),
        scan_salt=salt or ScanSalt.from_hex(FIXED_SALT_HEX),
        project_root=project_root or Path(),
        state_dir=state_dir,
    )


def write_fake_distribution(
    site_dir: Path,
    name: str,
    version: str,
    entry_points: Mapping[str, Mapping[str, str]],
    modules: Mapping[str, str],
) -> None:
    """Write an installed-looking distribution (``*.dist-info`` plus modules) into ``site_dir``."""
    info = site_dir / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
    )
    lines: list[str] = []
    for group, entries in entry_points.items():
        lines.append(f"[{group}]")
        lines.extend(f"{entry} = {target}" for entry, target in entries.items())
        lines.append("")
    (info / "entry_points.txt").write_text("\n".join(lines), encoding="utf-8")
    (info / "RECORD").write_text("", encoding="utf-8")
    for relative, source in modules.items():
        path = site_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def default_fake_stages() -> list[FakeStage]:
    """The eleven stages of the default pipeline as fakes (the E04-12 worked example)."""
    cat = StageCategory
    return [
        FakeStage("ingest", requires={"scan.target"}, provides={"files", "languages"},
                  category=cat.INGEST),
        FakeStage("parse", requires={"files"}, provides={"ast", "symbols", "callgraph"},
                  category=cat.PARSE),
        FakeStage("analyse-rules", requires={"files", "symbols"}, provides={"candidates.raw"},
                  category=cat.ANALYSE, parts={"candidates.raw": []}),
        FakeStage("analyse-taint", requires={"symbols", "callgraph"},
                  provides={"candidates.raw"}, category=cat.ANALYSE,
                  parts={"candidates.raw": []}),
        FakeStage("aggregate", requires={"candidates.raw"}, provides={"candidates"},
                  category=cat.AGGREGATE),
        FakeStage("privacy-prepare", requires={"candidates", "files"},
                  provides={"payloads.sanitised"}, category=cat.PRIVACY),
        FakeStage("llm-review", requires={"payloads.sanitised"}, provides={"verdicts.raw"},
                  category=cat.LLM),
        FakeStage("restore", requires={"verdicts.raw"}, provides={"verdicts.restored"},
                  category=cat.RESTORE),
        FakeStage("rate", requires={"candidates"}, provides={"findings", "scan.summary"},
                  optional_requires={"verdicts.restored"}, category=cat.RATE),
        FakeStage("report", requires={"findings"}, provides={"report.outputs"},
                  category=cat.REPORT),
        FakeStage("sync", requires={"findings"}, provides={"sync.result"}, category=cat.SYNC),
    ]  # fmt: skip


def layered_stage_infos(layers: int = 10, width: int = 50) -> list[StageInfo]:
    """``layers`` x ``width`` synthetic stages; each requires two keys of the previous layer.

    The first layer requires ``scan.target``. Names are ``l00-s00``, keys ``l00.k00``, so the
    graph is valid and resolvable; it is the graph of the pipeline budget tests (E04-32).
    """
    infos: list[StageInfo] = []
    for layer in range(layers):
        for index in range(width):
            if layer == 0:
                requires = frozenset({"scan.target"})
            else:
                previous = f"l{layer - 1:02d}"
                requires = frozenset(
                    {f"{previous}.k{index:02d}", f"{previous}.k{(index + 1) % width:02d}"}
                )
            infos.append(
                StageInfo(
                    name=f"l{layer:02d}-s{index:02d}",
                    requires=requires,
                    provides=frozenset({f"l{layer:02d}.k{index:02d}"}),
                )
            )
    return infos
