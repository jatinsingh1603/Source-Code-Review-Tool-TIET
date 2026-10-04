import re
import signal
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline import signals as signals_module
from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.resume import load_checkpoint
from codekavach.core.pipeline.runner import run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.signals import (
    FIRST_MESSAGE,
    SECOND_MESSAGE,
    cancel_on_signals,
)
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.layout import StateLayout
from tests.support.pipeline import FakeStage

HERE = "tests.unit.core.pipeline.test_signals"
PIPELINE = Path(signals_module.__file__).parent


def deliver(signum: signal.Signals) -> None:
    handler = signal.getsignal(signum)
    assert callable(handler)
    handler(signum, None)


def test_first_signal_cancels_and_second_exits(capfd: pytest.CaptureFixture[str]) -> None:
    token = CancellationToken()
    exits: list[int] = []
    original = signal.getsignal(signal.SIGINT)
    original_term = signal.getsignal(signal.SIGTERM)
    with cancel_on_signals(token, hard_exit=exits.append):
        assert signal.getsignal(signal.SIGINT) is not original
        deliver(signal.SIGINT)
        assert token.is_cancelled
        assert token.reason == "signal"
        assert exits == []
        assert capfd.readouterr().err == FIRST_MESSAGE
        deliver(signal.SIGTERM)
        assert exits == [130]
        assert capfd.readouterr().err == SECOND_MESSAGE
    assert signal.getsignal(signal.SIGINT) is original
    assert signal.getsignal(signal.SIGTERM) is original_term


def test_messages_are_the_fixed_strings() -> None:
    assert FIRST_MESSAGE == (
        "Cancelling... finishing the current stage. Press Ctrl-C again to exit immediately.\n"
    )
    assert SECOND_MESSAGE == "Exiting immediately; the scan can be resumed.\n"


def test_handlers_are_restored_after_an_exception() -> None:
    original = signal.getsignal(signal.SIGINT)
    with pytest.raises(RuntimeError), cancel_on_signals(CancellationToken()):
        raise RuntimeError("boom")
    assert signal.getsignal(signal.SIGINT) is original


def test_outside_the_main_thread_nothing_is_installed() -> None:
    original = signal.getsignal(signal.SIGINT)
    seen: list[object] = []
    errors: list[BaseException] = []

    def work() -> None:
        try:
            with cancel_on_signals(CancellationToken()):
                seen.append(signal.getsignal(signal.SIGINT))
        except BaseException as error:  # noqa: BLE001 - reported by the assertion
            errors.append(error)

    thread = threading.Thread(target=work)
    thread.start()
    thread.join(timeout=10)
    assert errors == []
    assert seen == [original]


def test_sigterm_registration_failure_is_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    real = signal.signal
    original = signal.getsignal(signal.SIGINT)

    def flaky(signum: int, handler: Any) -> Any:
        if signum == signal.SIGTERM:
            raise ValueError("signal not supported here")
        return real(signum, handler)

    monkeypatch.setattr(signal, "signal", flaky)
    token = CancellationToken()
    with cancel_on_signals(token, hard_exit=lambda _status: None):
        deliver(signal.SIGINT)
        assert token.reason == "signal"
    assert signal.getsignal(signal.SIGINT) is original


def test_cancel_from_a_handler_while_the_token_lock_is_held() -> None:
    # A handler runs in the main thread between bytecodes, possibly inside cancel() or child().
    token = CancellationToken()
    with token._lock:
        token.cancel("signal")
    assert token.reason == "signal"
    assert token.child().is_cancelled


def test_pipeline_has_no_untimed_join_wait_or_get() -> None:
    untimed = re.compile(r"\.join\(\)|\.wait\(\)|\.get\(\)")
    hits = [
        f"{path.name}:{number}"
        for path in sorted(PIPELINE.glob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if untimed.search(line)
    ]
    assert hits == []


class SignallingStage(FakeStage):
    """A slow stage that sends SIGINT to the process shortly after it has started."""

    def run(self, ctx: RunContext) -> None:
        threading.Timer(0.3, signal.raise_signal, args=(signal.SIGINT,)).start()
        super().run(ctx)


def slow() -> FakeStage:
    return SignallingStage(
        "ingest",
        requires={"scan.target"},
        provides={"files", "languages"},
        category=StageCategory.INGEST,
        sleep_seconds=60.0,
    )


def also_slow() -> FakeStage:
    return FakeStage(
        "warm-up",
        requires={"scan.target"},
        provides={"warmup.done"},
        category=StageCategory.INGEST,
        sleep_seconds=60.0,
    )


@pytest.mark.parametrize("stages", [("ingest",), ("ingest", "warm-up")], ids=["inline", "wave"])
def test_signal_during_a_scan_cancels_it_promptly(tmp_path: Path, stages: tuple[str, ...]) -> None:
    """The orchestrator's waits are sliced, so the handler runs while a stage is still busy."""
    targets = {"ingest": "slow", "warm-up": "also_slow"}
    registry = PluginRegistry(
        [
            PluginSpec("codekavach.stages", name, f"{HERE}:{targets[name]}", "p", "1")
            for name in stages
        ]
    )
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    loaded = load_settings(target=repo, env={"CODEKAVACH_HOME": str(tmp_path / "home")})
    original = signal.getsignal(signal.SIGINT)
    started = time.monotonic()
    outcome = run_scan(
        loaded, str(repo), salt=ScanSalt.generate(), registry=registry, handle_sigint=True
    )
    assert time.monotonic() - started < 30
    assert outcome.result.status is ScanStatus.CANCELLED
    assert signal.getsignal(signal.SIGINT) is original
    checkpoint = load_checkpoint(StateLayout(outcome.state_dir), outcome.scan.id)
    assert checkpoint is not None
    assert checkpoint.status == "cancelled"
