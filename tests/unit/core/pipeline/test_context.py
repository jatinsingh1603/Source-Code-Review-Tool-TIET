from datetime import UTC, datetime
from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.core.models import StageStatus
from codekavach.core.pipeline.budget import Budget
from codekavach.core.pipeline.cancel import CancellationToken, ScanCancelledError
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.events import Event, InMemoryEventBus, StageProgress, WarningRaised
from codekavach.core.pipeline.result import StageOutcome, StageRun
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.memory import InMemoryArtefactStore

SCAN = "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P"  # pragma: allowlist secret


class Clock:
    now = 0.0

    def __call__(self) -> float:
        return self.now


def context(budget: Budget | None = None) -> tuple[RunContext, list[Event]]:
    bus = InMemoryEventBus()
    seen: list[Event] = []
    bus.subscribe(seen.append)
    ctx = RunContext(
        scan_id=SCAN,
        config=Settings(),
        artefacts=InMemoryArtefactStore(),
        events=bus,
        cancellation=CancellationToken(),
        budget=budget or Budget(),
        scan_salt=ScanSalt.generate(),
        project_root=Path("repo"),
    )
    return ctx, seen


def test_for_stage_returns_a_bound_copy() -> None:
    ctx, _ = context()
    store = InMemoryArtefactStore()
    child = ctx.cancellation.child()
    bound = ctx.for_stage("parse", artefacts=store, cancellation=child)
    assert bound is not ctx
    assert (bound.stage, bound.artefacts, bound.cancellation) == ("parse", store, child)
    assert ctx.stage is None
    assert ctx.artefacts is not store
    assert bound.run_log is ctx.run_log
    assert ctx.for_stage("rate").artefacts is ctx.artefacts


def test_emit_progress_and_warn() -> None:
    ctx, seen = context()
    with pytest.raises(RuntimeError):
        ctx.emit_progress(1, 2, "files")
    ctx.warn("mock_provider_in_use")
    bound = ctx.for_stage("parse")
    bound.emit_progress(3, None, "files")
    bound.warn("slow_stage")
    assert isinstance(seen[0], WarningRaised)
    assert seen[0].stage is None
    progress = seen[1]
    assert isinstance(progress, StageProgress)
    assert (progress.stage, progress.current, progress.total, progress.unit) == (
        "parse", 3, None, "files",
    )  # fmt: skip
    assert seen[2].to_dict()["stage"] == "parse"


def test_check_cancelled() -> None:
    ctx, _ = context()
    ctx.check_cancelled()
    ctx.cancellation.cancel()
    with pytest.raises(ScanCancelledError, match="cancelled"):
        ctx.check_cancelled()


def test_check_cancelled_on_deadline() -> None:
    clock = Clock()
    budget = Budget(wall_seconds=5, monotonic=clock)
    budget.start()
    ctx, _ = context(budget)
    assert ctx.remaining_seconds() == 5
    clock.now = 6
    with pytest.raises(ScanCancelledError) as error:
        ctx.check_cancelled()
    assert error.value.reason == "deadline"
    assert ctx.cancellation.reason == "deadline"


def test_stage_runs() -> None:
    ctx, _ = context()
    run = StageRun(stage="parse", outcome=StageOutcome.SUCCEEDED)
    ctx.for_stage("parse").run_log.append(run)
    assert ctx.stage_runs() == (run,)


START = datetime(2026, 9, 24, 10, 0, tzinfo=UTC)
END = datetime(2026, 9, 24, 10, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("outcome", "status", "code"),
    [
        (StageOutcome.SUCCEEDED, StageStatus.SUCCEEDED, None),
        (StageOutcome.CACHED, StageStatus.SUCCEEDED, None),
        (StageOutcome.FAILED, StageStatus.FAILED, "engine_crashed"),
        (StageOutcome.TIMED_OUT, StageStatus.FAILED, "timeout"),
        (StageOutcome.SKIPPED, StageStatus.SKIPPED, None),
        (StageOutcome.CANCELLED, StageStatus.SKIPPED, None),
    ],
)
def test_to_stage_result(outcome: StageOutcome, status: StageStatus, code: str | None) -> None:
    run = StageRun(
        stage="analyse-rules",
        outcome=outcome,
        started_at=START,
        finished_at=END,
        duration_ms=60000,
        error_code="engine_crashed" if outcome is StageOutcome.FAILED else None,
        error_type="RuntimeError" if code else None,
        items_in=3,
        items_out=2,
    )
    result = run.to_stage_result()
    assert (result.name, result.status, result.error_code) == ("analyse-rules", status, code)
    assert result.error_summary is None
    assert (result.items_in, result.items_out) == (3, 2)


def test_failed_without_code_gets_fallback() -> None:
    run = StageRun(stage="parse", outcome=StageOutcome.FAILED)
    assert run.to_stage_result().error_code == "stage_failed"
