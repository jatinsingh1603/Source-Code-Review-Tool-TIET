import dataclasses
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from codekavach.core.log import configure_logging
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.cancel import ScanCancelledError
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.errors import UnsatisfiedRequirementError
from codekavach.core.pipeline.events import NullEventBus
from codekavach.core.pipeline.orchestrator import Orchestrator, error_type_of
from codekavach.core.pipeline.plan import RunPlan, plan_from_stages
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.stage import StageCategory
from tests.support.golden import assert_matches_golden
from tests.support.pipeline import CollectingBus, FakeStage, make_run_context

GOLDEN = Path(__file__).parent / "golden" / "orchestrator_events.json"
MARKER = "PLANTEDSOURCELINE"
C = StageCategory


class Clocks:
    def __init__(self) -> None:
        self.wall = datetime(2026, 9, 24, 10, 0, tzinfo=UTC)
        self.ticks = 0.0

    def clock(self) -> datetime:
        self.wall += timedelta(seconds=1)
        return self.wall

    def monotonic(self) -> float:
        self.ticks += 0.25
        return self.ticks


def orchestrator() -> Orchestrator:
    clocks = Clocks()
    return Orchestrator(clock=clocks.clock, monotonic=clocks.monotonic)


def chain(b: FakeStage | None = None) -> list[FakeStage]:
    return [
        FakeStage("a", requires={"scan.target"}, provides={"x"}, category=C.ANALYSE),
        b or FakeStage("b", requires={"x"}, provides={"y"}, category=C.ANALYSE),
        FakeStage("c", requires={"y"}, provides={"z"}, category=C.ANALYSE),
    ]


def prepared(stages: list[FakeStage], **kwargs: Any) -> tuple[RunPlan, RunContext]:
    ctx = make_run_context(**kwargs)
    ctx.artefacts.put("scan.target", {"target": "repo"})
    return plan_from_stages(stages), ctx


def kinds(ctx: RunContext) -> list[str]:
    assert isinstance(ctx.events, CollectingBus)
    return ctx.events.kinds()


def test_success_path() -> None:
    plan, ctx = prepared(chain())
    result = orchestrator().run(plan, ctx)
    assert result.status is ScanStatus.COMPLETED
    assert [(run.stage, run.outcome) for run in result.stage_runs] == [
        ("a", StageOutcome.SUCCEEDED),
        ("b", StageOutcome.SUCCEEDED),
        ("c", StageOutcome.SUCCEEDED),
    ]
    assert result.produced_keys == ("x", "y", "z")
    assert result.failed_stages() == ()
    assert result.run_of("b") is not None
    assert ctx.stage_runs() == result.stage_runs
    assert result.stage_runs[0].duration_ms == 250


def test_success_events_golden() -> None:
    plan, ctx = prepared(chain())
    orchestrator().run(plan, ctx)
    assert isinstance(ctx.events, CollectingBus)
    events = [event.to_dict() for event in ctx.events.events]
    for event in events:
        event["at"] = "fixed"
    assert_matches_golden(json.dumps(events, indent=2) + "\n", GOLDEN)


@pytest.mark.parametrize("write_before", [True, False])
def test_failure_path(write_before: bool) -> None:
    failing = FakeStage(
        "b",
        requires={"x"},
        provides={"y"},
        category=C.ANALYSE,
        raises=ValueError(MARKER),
        write_before_raise=write_before,
    )
    plan, ctx = prepared(chain(failing))
    result = orchestrator().run(plan, ctx)
    assert kinds(ctx) == [
        "scan.started", "plan.resolved", "stage.started", "stage.finished", "stage.started",
        "stage.failed", "stage.skipped", "scan.finished",
    ]  # fmt: skip
    assert isinstance(ctx.events, CollectingBus)
    failed = ctx.events.of("stage.failed")[0].to_dict()
    assert (failed["stage"], failed["error_type"], failed["policy"]) == (
        "b", "ValueError", "abort_scan",
    )  # fmt: skip
    skipped = ctx.events.of("stage.skipped")[0].to_dict()
    assert (skipped["stage"], skipped["reason_code"]) == ("c", "scan_aborted")
    assert ctx.events.of("scan.finished")[0].to_dict()["status"] == "failed"
    assert (ctx.artefacts.has("x"), ctx.artefacts.has("y"), ctx.artefacts.has("z")) == (
        True, False, False,
    )  # fmt: skip
    assert result.status is ScanStatus.FAILED
    assert [run.outcome for run in result.stage_runs] == [
        StageOutcome.SUCCEEDED, StageOutcome.FAILED, StageOutcome.SKIPPED,
    ]  # fmt: skip
    assert result.run_of("b").error_code == "stage_exception"  # type: ignore[union-attr]
    assert result.failed_stages() == ("b",)
    assert result.produced_keys == ("x",)


def test_failed_part_is_discarded_only_for_that_stage() -> None:
    stages = [
        FakeStage("analyse-a", requires={"scan.target"}, provides={"candidates.raw"},
                  parts={"candidates.raw": []}, category=C.ANALYSE),
        FakeStage("analyse-b", requires={"scan.target"}, provides={"candidates.raw"},
                  parts={"candidates.raw": []}, category=C.ANALYSE, raises=RuntimeError("x")),
    ]  # fmt: skip
    plan, ctx = prepared(stages)
    orchestrator().run(plan, ctx)
    ref = ctx.artefacts.ref("candidates.raw")
    assert ref is not None
    assert [part for part, _ in ref.parts] == ["analyse-a"]


def test_missing_provides() -> None:
    lazy = FakeStage("b", requires={"x"}, provides={"y"}, category=C.ANALYSE, writes={})
    plan, ctx = prepared(chain(lazy))
    result = orchestrator().run(plan, ctx)
    run = result.run_of("b")
    assert run is not None
    assert (run.outcome, run.error_code) == (StageOutcome.FAILED, "missing_provides")


class CancellingStage(FakeStage):
    def run(self, ctx: RunContext) -> None:
        super().run(ctx)
        ctx.cancellation.cancel()


def test_cancellation_between_stages() -> None:
    first = CancellingStage("a", requires={"scan.target"}, provides={"x"}, category=C.ANALYSE)
    plan, ctx = prepared([first, *chain()[1:]])
    result = orchestrator().run(plan, ctx)
    assert result.status is ScanStatus.CANCELLED
    assert [run.outcome for run in result.stage_runs] == [
        StageOutcome.SUCCEEDED, StageOutcome.CANCELLED, StageOutcome.CANCELLED,
    ]  # fmt: skip
    assert kinds(ctx)[-1] == "scan.cancelled"


def test_cancellation_inside_a_stage() -> None:
    raising = FakeStage("b", requires={"x"}, provides={"y"}, category=C.ANALYSE,
                        raises=ScanCancelledError())  # fmt: skip
    plan, ctx = prepared(chain(raising))
    result = orchestrator().run(plan, ctx)
    assert result.status is ScanStatus.CANCELLED
    assert [run.outcome for run in result.stage_runs][1:] == [
        StageOutcome.CANCELLED, StageOutcome.CANCELLED,
    ]  # fmt: skip
    assert not ctx.artefacts.has("y")
    assert "stage.failed" not in kinds(ctx)


def test_missing_initial_key() -> None:
    plan = plan_from_stages(chain())
    ctx = make_run_context()
    with pytest.raises(UnsatisfiedRequirementError):
        orchestrator().run(plan, ctx)
    assert kinds(ctx) == []


def test_dependency_missing_is_skipped() -> None:
    stages = [*chain()[:2], FakeStage("c", requires={"y", "scan.target"}, provides={"z"},
                                       category=C.ANALYSE)]  # fmt: skip
    plan, ctx = prepared(stages)

    class Vanishing(Orchestrator):
        def _execute_stage(self, stage: Any, info: Any, stage_ctx: RunContext) -> None:
            super()._execute_stage(stage, info, stage_ctx)
            if info.name == "a":
                stage_ctx.artefacts.discard("scan.target")

    result = Vanishing().run(plan, ctx)
    run = result.run_of("c")
    assert run is not None
    assert (run.outcome, run.skip_reason, run.blocked_by) == (
        StageOutcome.SKIPPED, "dependency_missing", "initial",
    )  # fmt: skip
    assert result.status is ScanStatus.COMPLETED
    assert "stage.skipped" in kinds(ctx)


def test_null_bus_gives_the_same_result() -> None:
    plan, collecting = prepared(chain())
    _, silent = prepared(chain(), bus=NullEventBus())
    first = orchestrator().run(plan, collecting)
    second = orchestrator().run(plan_from_stages(chain()), silent)
    assert dataclasses.replace(first, started_at=None, finished_at=None) == dataclasses.replace(
        second, started_at=None, finished_at=None
    )


def test_keyboard_interrupt_propagates_and_discards() -> None:
    interrupted = FakeStage("b", requires={"x"}, provides={"y"}, category=C.ANALYSE,
                            raises=KeyboardInterrupt())  # fmt: skip
    plan, ctx = prepared(chain(interrupted))
    with pytest.raises(KeyboardInterrupt):
        orchestrator().run(plan, ctx)
    assert not ctx.artefacts.has("y")


def test_logs_carry_class_names_only(log_output: io.StringIO) -> None:
    failing = FakeStage("b", requires={"x"}, provides={"y"}, category=C.ANALYSE,
                        raises=ValueError(MARKER))  # fmt: skip
    plan, ctx = prepared(chain(failing))
    configure_logging(fmt="json", level="INFO", stream=log_output, force=True)
    orchestrator().run(plan, ctx)
    output = log_output.getvalue()
    assert "ValueError" in output
    assert "stage_failed" in output
    assert MARKER not in output


def test_error_type_is_event_safe() -> None:
    class LocalError(Exception):
        pass

    assert error_type_of(LocalError()) == "test_error_type_is_event_safe._locals_.LocalError"
    assert error_type_of(ValueError()) == "ValueError"
