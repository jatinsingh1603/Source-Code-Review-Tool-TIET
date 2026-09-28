import time
from typing import Any

import pytest

from codekavach.config.models.scan import ScanSettings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline import orchestrator as orchestrator_module
from codekavach.core.pipeline.budget import Budget
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.events import WarningRaised
from codekavach.core.pipeline.execution import resolve_timeout, run_with_deadline
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.stage import StageCategory, StageInfo
from tests.support.pipeline import CollectingBus, FakeStage, default_fake_stages, make_run_context

C = StageCategory


def info(name: str, category: StageCategory | None, timeout: int | None = None) -> StageInfo:
    return StageInfo(
        name=name,
        requires=frozenset(),
        provides=frozenset(),
        category=category,
        timeout_seconds=timeout,
    )


# resolve_timeout


def test_precedence_example() -> None:
    settings = ScanSettings(stage_timeouts={"analyse": 600, "analyse-taint": 1200})
    assert resolve_timeout(info("analyse-taint", C.ANALYSE), settings, None) == 1200
    assert resolve_timeout(info("analyse-rules", C.ANALYSE), settings, None) == 600
    assert resolve_timeout(info("parse", C.PARSE), settings, None) == 1800
    assert resolve_timeout(info("custom", None, timeout=300), settings, None) == 300
    assert resolve_timeout(info("analyse-taint", C.ANALYSE, timeout=30), settings, None) == 1200


def test_capped_by_remaining_scan_time() -> None:
    settings = ScanSettings()
    assert resolve_timeout(info("parse", C.PARSE), settings, 5.0) == 5.0
    assert resolve_timeout(info("parse", C.PARSE), settings, -3.0) == 0.0
    assert resolve_timeout(info("parse", C.PARSE), settings, 99999.0) == 1800


# run_with_deadline


def test_run_with_deadline_outcomes() -> None:
    assert run_with_deadline(lambda: None, 1.0, thread_name="t").outcome == "completed"
    slow = run_with_deadline(lambda: time.sleep(0.5), 0.05, thread_name="t")
    assert slow.outcome == "timed_out"
    assert slow.thread.daemon
    error = ValueError("boom")

    def fail() -> None:
        raise error

    raised = run_with_deadline(fail, 1.0, thread_name="t")
    assert raised.outcome == "exception"
    assert raised.error is error


# orchestrator


@pytest.fixture
def short_timeouts(monkeypatch: pytest.MonkeyPatch) -> dict[str, float]:
    """Per-stage timeouts in seconds; stages not listed get 5 s."""
    limits: dict[str, float] = {}
    monkeypatch.setattr(
        orchestrator_module,
        "resolve_timeout",
        lambda stage_info, *_: limits.get(stage_info.name, 5.0),
    )
    return limits


class TokenRecordingStage(FakeStage):
    def run(self, ctx: RunContext) -> None:
        self.token = ctx.cancellation
        super().run(ctx)


def chain(b: FakeStage) -> list[FakeStage]:
    return [
        FakeStage("a", requires={"scan.target"}, provides={"x"}, category=C.ANALYSE),
        b,
        FakeStage("c", requires={"x"}, provides={"z"}, category=C.ANALYSE),
    ]


def prepared(stages: list[FakeStage], **kwargs: Any) -> tuple[Any, RunContext]:
    ctx = make_run_context(**kwargs)
    ctx.artefacts.put("scan.target", {"target": "repo"})
    return plan_from_stages(stages), ctx


def test_cooperative_stage_times_out(short_timeouts: dict[str, float]) -> None:
    short_timeouts["b"] = 0.1
    slow = TokenRecordingStage(
        "b", requires={"x"}, provides={"y"}, category=C.ANALYSE, sleep_seconds=2.0
    )
    plan, ctx = prepared(chain(slow))
    started = time.monotonic()
    result = Orchestrator().run(plan, ctx)
    assert time.monotonic() - started < 0.5
    run = result.run_of("b")
    assert run is not None
    assert (run.outcome, run.error_code, run.error_type) == (
        StageOutcome.TIMED_OUT,
        "stage_timeout",
        "TimeoutError",
    )
    assert slow.token.reason == "timeout"
    assert not ctx.artefacts.has("y")
    assert result.status is ScanStatus.COMPLETED_WITH_ERRORS  # ANALYSE degrades; c still ran
    c_run = result.run_of("c")
    assert c_run is not None
    assert c_run.outcome is StageOutcome.SUCCEEDED


def test_non_cooperative_late_write_is_rejected(short_timeouts: dict[str, float]) -> None:
    short_timeouts["b"] = 0.1
    stubborn = FakeStage(
        "b",
        requires={"x"},
        provides={"y"},
        category=C.ANALYSE,
        sleep_seconds=0.3,
        cooperative=False,
    )
    plan, ctx = prepared(chain(stubborn))
    result = Orchestrator().run(plan, ctx)
    assert result.abandoned_threads == 1
    time.sleep(0.4)  # let the abandoned thread attempt its late write
    assert not ctx.artefacts.has("y")


def test_timed_out_privacy_stage_locks_egress(short_timeouts: dict[str, float]) -> None:
    short_timeouts["privacy-prepare"] = 0.1
    stages = default_fake_stages()
    by_name = {stage.name: stage for stage in stages}
    by_name["privacy-prepare"]._sleep_seconds = 2.0
    ctx = make_run_context()
    ctx.artefacts.put("scan.target", {"target": "repo"})
    result = Orchestrator().run(plan_from_stages(stages), ctx)
    run = result.run_of("privacy-prepare")
    assert run is not None
    assert run.outcome is StageOutcome.TIMED_OUT
    assert result.egress_locked
    assert by_name["llm-review"].calls == 0


def test_scan_deadline_cancels_remaining_stages() -> None:
    now = [0.0]
    budget = Budget(wall_seconds=10, monotonic=lambda: now[0])

    class Slow(FakeStage):
        def run(self, ctx: RunContext) -> None:
            super().run(ctx)
            now[0] += 60  # the scan budget is used up while this stage runs

    bus = CollectingBus()
    first = Slow("a", requires={"scan.target"}, provides={"x"}, category=C.ANALYSE)
    rest = [
        FakeStage("b", requires={"x"}, provides={"y"}, category=C.ANALYSE),
        FakeStage("c", requires={"y"}, provides={"z"}, category=C.ANALYSE),
    ]
    plan, ctx = prepared([first, *rest], budget=budget, bus=bus)
    result = Orchestrator().run(plan, ctx)
    assert result.status is ScanStatus.CANCELLED
    assert [run.outcome for run in result.stage_runs] == [
        StageOutcome.SUCCEEDED,
        StageOutcome.CANCELLED,
        StageOutcome.CANCELLED,
    ]
    assert ctx.cancellation.reason == "deadline"
    warnings = [
        event
        for event in bus.of("warning")
        if isinstance(event, WarningRaised) and event.code == "scan_deadline"
    ]
    assert len(warnings) == 1
