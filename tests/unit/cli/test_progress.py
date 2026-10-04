import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import pytest
import typer
from rich.console import Console

from codekavach.cli import progress as progress_module
from codekavach.cli.app import app
from codekavach.cli.progress import (
    BarRenderer,
    JsonRenderer,
    PlainRenderer,
    ProgressMode,
    Renderer,
    json_fields,
    known_kind,
    progress_listener,
    resolve_mode,
)
from codekavach.core.pipeline.events import (
    Event,
    InMemoryEventBus,
    ItemFailed,
    PlanResolved,
    ScanCancelled,
    ScanFinished,
    ScanStarted,
    StageFailed,
    StageFinished,
    StageProgress,
    StageSkipped,
    StageStarted,
    WarningRaised,
)
from tests.support.cli import CliResult
from tests.support.scan_stub import install_stub

Cli = Callable[..., CliResult]
SCAN = "scan_01ARYZ6S410000000000000000"
SECRET = "password = 'x'"
SEEN: dict[str, Any] = {}

SCRIPT: tuple[Event, ...] = (
    ScanStarted(scan_id=SCAN, stage_count=2),
    PlanResolved(scan_id=SCAN, stages=("ingest", "parse"), wave_sizes=(1, 1)),
    StageStarted(scan_id=SCAN, stage="ingest", index=0, total=2),
    StageFinished(scan_id=SCAN, stage="ingest", outcome="succeeded", duration_ms=200),
    StageStarted(scan_id=SCAN, stage="parse", index=1, total=2),
    StageProgress(scan_id=SCAN, stage="parse", current=64, total=128, unit="files"),
    StageFinished(scan_id=SCAN, stage="parse", outcome="succeeded", duration_ms=842),
    ScanFinished(scan_id=SCAN, status="completed", duration_ms=1100, findings_total=3),
)
PLAIN_LINES = [
    "[ingest] started",
    "[ingest] finished 0.2s",
    "[parse] started",
    "[parse] 64/128",
    "[parse] finished 0.8s",
]


class LeakyFailed(StageFailed):
    """A subclass defined outside the pipeline that carries text an event must not carry."""

    error: ClassVar[str] = SECRET
    snippet: ClassVar[str] = SECRET


@dataclass(frozen=True)
class Foreign:
    """Not an event class of the pipeline, although it looks like one."""

    kind: ClassVar[str] = "stage.progress"
    scan_id: str = SCAN
    stage: str = "parse"
    current: int = 1
    total: int = 2
    message: str = "\x1b[31m" + "x" * 500
    snippet: str = SECRET


def leaky() -> list[Any]:
    failed = LeakyFailed(
        scan_id=SCAN,
        stage="parse",
        policy="degrade",
        error_code="stage_exception",
        error_type="RuntimeError",
        duration_ms=5,
    )
    return [failed, Foreign()]


@pytest.fixture
def probe() -> Iterator[None]:
    """A temporary ``mode`` command that records what ``--progress`` resolves to."""

    def command(ctx: typer.Context, progress: ProgressMode = ProgressMode.auto) -> None:
        SEEN["mode"] = resolve_mode(progress, ctx)

    app.command("mode")(command)
    try:
        yield
    finally:
        app.registered_commands[:] = [c for c in app.registered_commands if c.name != "mode"]
        SEEN.clear()


def resolved(cli: Cli, *args: str, **kwargs: Any) -> ProgressMode:
    SEEN.clear()
    result = cli(["mode", *args], **kwargs)
    assert result.exit_code == 0, result.stderr
    mode = SEEN["mode"]
    assert isinstance(mode, ProgressMode)
    return mode


# resolve_mode


def test_auto_resolution(cli: Cli, probe: None) -> None:
    assert resolved(cli, tty=True) is ProgressMode.bar
    assert resolved(cli, tty=False) is ProgressMode.plain
    assert resolved(cli, "--quiet", tty=True) is ProgressMode.off
    assert resolved(cli, "--json", tty=True) is ProgressMode.off
    assert resolved(cli, tty=True, env={"CI": "true"}) is ProgressMode.plain
    assert resolved(cli, "--no-input", tty=True) is ProgressMode.plain


@pytest.mark.parametrize("mode", [mode for mode in ProgressMode if mode is not ProgressMode.auto])
def test_explicit_values_are_kept(cli: Cli, probe: None, mode: ProgressMode) -> None:
    assert resolved(cli, "--progress", mode.value, "--quiet", tty=False) is mode
    assert resolved(cli, "--progress", mode.value, "--json", tty=True) is mode


# plain


def test_plain_lines_for_the_script() -> None:
    lines: list[str] = []
    renderer = PlainRenderer(write=lines.append, clock=lambda: 0.0)
    for event in SCRIPT:
        renderer.handle(event)
    assert lines == PLAIN_LINES


def test_plain_progress_is_throttled_per_stage() -> None:
    lines: list[str] = []
    now = [0.0]
    renderer = PlainRenderer(write=lines.append, clock=lambda: now[0])

    def progress(stage: str, current: int, total: int | None = 100) -> None:
        renderer.handle(
            StageProgress(scan_id=SCAN, stage=stage, current=current, total=total, unit="files")
        )

    progress("parse", 1)
    now[0] = 4.9
    progress("parse", 2)
    progress("rules", 7, None)
    now[0] = 5.0
    progress("parse", 3)
    now[0] = 9.9
    progress("parse", 4)
    progress("rules", 8, None)
    now[0] = 10.0
    progress("parse", 5)
    renderer.handle(StageFinished(scan_id=SCAN, stage="parse", outcome="cached", duration_ms=0))
    progress("parse", 6)
    assert lines == [
        "[parse] 1/100",
        "[rules] 7",
        "[parse] 3/100",
        "[rules] 8",
        "[parse] 5/100",
        "[parse] finished 0.0s (cached)",
        "[parse] 6/100",
    ]


def test_plain_failed_stage_shows_policy_only() -> None:
    lines: list[str] = []
    renderer = PlainRenderer(write=lines.append)
    renderer.handle(
        StageFailed(
            scan_id=SCAN,
            stage="taint",
            policy="degrade",
            error_code="stage_exception",
            error_type="RuntimeError",
            duration_ms=12,
        )
    )
    assert lines == ["stage taint failed (degrade)"]


# json

ALLOWED = {
    "scan.started": {"event", "scan_id", "total_stages"},
    "plan.resolved": {"event", "order"},
    "stage.started": {"event", "stage", "index", "total"},
    "stage.progress": {"event", "stage", "current", "total"},
    "stage.finished": {"event", "stage", "duration_s", "from_cache"},
    "stage.failed": {"event", "stage", "policy", "error_type"},
    "scan.finished": {"event", "scan_id", "duration_s", "finding_count"},
    "scan.cancelled": {"event", "scan_id"},
}
EVERY_EVENT: tuple[Event, ...] = (
    *SCRIPT,
    StageFailed(
        scan_id=SCAN,
        stage="taint",
        policy="fail_closed",
        error_code="stage_exception",
        error_type="ValueError",
        duration_ms=7,
    ),
    ScanCancelled(scan_id=SCAN, stages_completed=1),
    StageSkipped(scan_id=SCAN, stage="report", reason_code="dependency_failed"),
    ItemFailed(scan_id=SCAN, stage="privacy-prepare", item_id="cand_1", error_code="redaction"),
    WarningRaised(scan_id=SCAN, stage="aggregate", code="partial_input"),
)


def test_json_lines_hold_only_allow_listed_keys() -> None:
    lines: list[str] = []
    renderer = JsonRenderer(write=lines.append)
    for event in EVERY_EVENT:
        renderer.handle(event)
    documents = [json.loads(line) for line in lines]
    assert all("\n" not in line and " " not in line for line in lines)
    assert {document["event"] for document in documents} == set(ALLOWED)
    for document in documents:
        assert set(document) == ALLOWED[document["event"]]
    finished = next(
        d for d in documents if d["event"] == "stage.finished" and d["stage"] == "parse"
    )
    assert finished == {
        "event": "stage.finished",
        "stage": "parse",
        "duration_s": 0.842,
        "from_cache": False,
    }
    assert documents[0] == {"event": "scan.started", "scan_id": SCAN, "total_stages": 2}
    assert documents[-2]["error_type"] == "ValueError"


def test_events_outside_the_allow_list_have_no_fields() -> None:
    for event in EVERY_EVENT[-3:]:
        assert known_kind(event) is not None
        assert json_fields(event) is None


# leakage


def test_foreign_and_subclassed_events_are_ignored_in_every_mode() -> None:
    lines: list[str] = []
    console = Console(record=True, force_terminal=False, width=100)
    bar = BarRenderer(console)
    renderers: list[Renderer] = [
        PlainRenderer(write=lines.append),
        JsonRenderer(write=lines.append),
        bar,
    ]
    for event in leaky():
        assert known_kind(event) is None
        for renderer in renderers:
            renderer.handle(event)
    assert lines == []
    assert bar.stage_state("parse") is None
    assert SECRET not in console.export_text()


def test_failed_stage_never_shows_more_than_policy_and_type() -> None:
    lines: list[str] = []
    failed = StageFailed(
        scan_id=SCAN,
        stage="parse",
        policy="degrade",
        error_code="stage_exception",
        error_type="RuntimeError",
        duration_ms=5,
    )
    PlainRenderer(write=lines.append).handle(failed)
    JsonRenderer(write=lines.append).handle(failed)
    assert lines[0] == "stage parse failed (degrade)"
    assert json.loads(lines[1]) == {
        "event": "stage.failed",
        "stage": "parse",
        "policy": "degrade",
        "error_type": "RuntimeError",
    }


# bar


def test_bar_tracks_tasks_and_prints_completed_lines() -> None:
    console = Console(record=True, force_terminal=False, width=100)
    bar = BarRenderer(console)
    bar.start()
    try:
        for event in SCRIPT[:6]:
            bar.handle(event)
        assert bar.stage_state("parse") == (64, 128)
        assert bar.stage_state("ingest") is None
        for event in SCRIPT[6:]:
            bar.handle(event)
        bar.handle(StageFinished(scan_id=SCAN, stage="rules", outcome="cached", duration_ms=0))
    finally:
        bar.stop()
    assert not bar.progress.live.is_started
    text = console.export_text()
    assert "ingest  0.2s" in text
    assert "parse  0.8s" in text
    assert "rules  0.0s (cached)" in text


def test_bar_survives_concurrent_progress_events() -> None:
    bar = BarRenderer(Console(record=True, force_terminal=False, width=100))
    errors: list[BaseException] = []

    def publish(stage: str) -> None:
        try:
            for current in range(1, 201):
                bar.handle(
                    StageProgress(
                        scan_id=SCAN, stage=stage, current=current, total=200, unit="files"
                    )
                )
        except BaseException as error:  # noqa: BLE001 - reported by the assertion
            errors.append(error)

    stages = [f"stage-{index}" for index in range(8)]
    bar.start()
    try:
        threads = [threading.Thread(target=publish, args=(stage,)) for stage in stages]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
    finally:
        bar.stop()
    assert errors == []
    assert [bar.stage_state(stage) for stage in stages] == [(200, 200)] * 8


# the listener


class Subscriptions(InMemoryEventBus):
    """A bus that counts its live subscriptions."""

    def __init__(self) -> None:
        super().__init__()
        self.active = 0

    def subscribe(self, handler: Callable[[Event], None]) -> Callable[[], None]:
        unsubscribe = super().subscribe(handler)
        self.active += 1

        def remove() -> None:
            self.active -= 1
            unsubscribe()

        return remove


@pytest.fixture
def listen() -> Iterator[None]:
    """A temporary ``listen`` command that runs a scripted block inside ``progress_listener``."""

    def command(
        ctx: typer.Context, progress: ProgressMode = ProgressMode.auto, fail: str = ""
    ) -> None:
        bus = Subscriptions()
        SEEN["bus"] = bus
        with progress_listener(ctx, bus, progress):
            SEEN["active_inside"] = bus.active
            for event in SCRIPT:
                bus.publish(event)
            if fail == "interrupt":
                raise KeyboardInterrupt
            if fail == "error":
                raise RuntimeError("boom")
        typer.echo("RESULT")

    app.command("listen")(command)
    try:
        yield
    finally:
        app.registered_commands[:] = [c for c in app.registered_commands if c.name != "listen"]
        SEEN.clear()


@pytest.fixture
def bars(monkeypatch: pytest.MonkeyPatch) -> list[BarRenderer]:
    made: list[BarRenderer] = []

    class Recording(BarRenderer):
        def __init__(self, console: Console) -> None:
            super().__init__(console)
            made.append(self)

    monkeypatch.setattr(progress_module, "BarRenderer", Recording)
    return made


@pytest.mark.parametrize(("fail", "exit_code"), [("", 0), ("error", 4), ("interrupt", 130)])
def test_listener_tears_down_however_the_block_ends(
    cli: Cli, listen: None, bars: list[BarRenderer], fail: str, exit_code: int
) -> None:
    args = ["listen", "--fail", fail] if fail else ["listen"]
    result = cli(args, tty=True)
    assert result.exit_code == exit_code
    assert SEEN["active_inside"] == 1
    assert SEEN["bus"].active == 0
    assert len(bars) == 1
    assert bars[0].progress.live.is_started is False
    assert "parse  0.8s" in result.stderr
    assert result.stdout == ("" if fail else "RESULT\n")


def test_listener_modes_through_the_command(cli: Cli, listen: None) -> None:
    plain = cli(["listen"], tty=False)
    assert plain.stderr.splitlines() == PLAIN_LINES
    assert plain.stdout == "RESULT\n"
    assert cli(["listen", "--quiet"], tty=True).stderr == ""
    assert cli(["listen", "--progress", "off"], tty=False).stderr == ""
    assert SEEN["active_inside"] == 0


# scan


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def test_scan_shows_a_live_display_on_a_terminal(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, bars: list[BarRenderer]
) -> None:
    install_stub(monkeypatch, events=SCRIPT)
    result = cli(["scan", str(project), "--fail-on", "none"], tty=True)
    assert result.exit_code == 0, result.stderr
    assert len(bars) == 1
    assert bars[0].progress.live.is_started is False
    assert "ingest  0.2s" in result.stderr
    assert "parse  0.8s" in result.stderr
    assert "parse" not in result.stdout
    assert "findings:" in result.stdout


def test_scan_plain_quiet_and_json(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_stub(monkeypatch, events=SCRIPT)
    base = ["scan", str(project), "--fail-on", "none"]
    plain = cli(base, tty=False)
    assert [line for line in plain.stderr.splitlines() if line.startswith("[")] == PLAIN_LINES
    assert "[parse]" not in plain.stdout
    quiet = cli([*base, "--quiet"], tty=True)
    assert "parse" not in quiet.stderr
    machine = cli([*base, "--json"], tty=True)
    assert "parse" not in machine.stderr
    assert machine.json["command"] == "scan"


def test_scan_json_progress_and_one_envelope(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_stub(monkeypatch, events=[*SCRIPT, leaky()[0]])  # the bus accepts events only
    result = cli(["scan", str(project), "--fail-on", "none", "--json", "--progress", "json"])
    assert result.exit_code == 0, result.stderr
    assert result.json["exit_code"] == 0
    documents = [json.loads(line) for line in result.stderr.splitlines() if line.strip()]
    assert [document["event"] for document in documents] == [event.kind for event in SCRIPT]
    assert SECRET not in result.stderr
    assert SECRET not in result.stdout
    for mode in ("plain", "bar"):
        shown = cli(["scan", str(project), "--fail-on", "none", "--progress", mode])
        assert SECRET not in shown.stderr
        assert "\x1b[31m" not in shown.stderr


def test_scan_stops_the_display_on_interrupt(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, bars: list[BarRenderer]
) -> None:
    install_stub(monkeypatch, events=SCRIPT[:5], error=KeyboardInterrupt())
    result = cli(["scan", str(project)], tty=True)
    assert result.exit_code == 130
    assert len(bars) == 1
    assert bars[0].progress.live.is_started is False
