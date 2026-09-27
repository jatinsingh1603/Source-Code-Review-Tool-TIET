"""The orchestrator: runs a ``RunPlan`` stage by stage.

Owning epic: E04.

Per stage, in resolved order: stop if cancelled; skip when a hard requirement is absent (naming the
stage that should have provided it); run the stage through ``_execute_stage``; check that every
declared output was written; record a ``StageRun`` and publish lifecycle events. In this module any
stage failure ends the run (the conservative default for I4): the failed stage's outputs are
discarded, so nothing half-prepared can be consumed, and every later stage is skipped. The
differentiated failure policies, per-stage store isolation, timeouts and concurrency are layered on
``_execute_stage`` and ``_failed`` by later issues.

Default-level logs and events carry exception class names only; exception messages, which parsers
and engines often fill with a quoted source line, appear only in a DEBUG record.
"""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from codekavach.core.log import get_logger
from codekavach.core.models import ScanStatus
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline.cancel import ScanCancelledError
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.errors import UnsatisfiedRequirementError
from codekavach.core.pipeline.events import (
    PlanResolved,
    ScanCancelled,
    ScanFinished,
    ScanStarted,
    StageFailed,
    StageFinished,
    StageSkipped,
    StageStarted,
)
from codekavach.core.pipeline.keys import is_multi_provider
from codekavach.core.pipeline.plan import RunPlan
from codekavach.core.pipeline.result import PipelineResult, StageOutcome, StageRun
from codekavach.core.pipeline.stage import Stage, StageInfo

INITIAL = "<initial>"
INITIAL_PROVIDER = "initial"  # event-safe name of the initial keys as a provider
_TOKEN_UNSAFE = re.compile(r"[^A-Za-z0-9_.:-]")
_log = get_logger("codekavach.pipeline")


def error_type_of(error: BaseException) -> str:
    """The exception's qualified class name, made safe for events (``<locals>`` and the like)."""
    name = _TOKEN_UNSAFE.sub("_", type(error).__qualname__)[:64]
    return name or "Exception"


class _MissingProvidesError(Exception):
    """Internal: a stage returned without writing one of its declared outputs."""


@dataclass(frozen=True, slots=True)
class _Timing:
    started_at: datetime
    finished_at: datetime
    duration_ms: int


class Orchestrator:
    """Runs the stages of a plan in order."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self._monotonic = monotonic

    def _execute_stage(self, stage: Stage, info: StageInfo, stage_ctx: RunContext) -> None:
        """Run one stage; later issues wrap this with isolation, timeouts and threads."""
        stage.run(stage_ctx)

    @staticmethod
    def _discard_outputs(info: StageInfo, ctx: RunContext) -> None:
        for key in sorted(info.provides):
            if is_multi_provider(key):
                ctx.artefacts.discard(key, part=info.name)
            else:
                ctx.artefacts.discard(key)

    @staticmethod
    def _provider_of(plan: RunPlan, key: str) -> str:
        for name in plan.order:
            if key in plan.infos[name].provides:
                return name
        return INITIAL_PROVIDER

    @staticmethod
    def _record(ctx: RunContext, runs: list[StageRun], run: StageRun) -> None:
        runs.append(run)
        ctx.run_log.append(run)

    def _skip_blocked(
        self, plan: RunPlan, ctx: RunContext, runs: list[StageRun], info: StageInfo
    ) -> bool:
        """Record a skip when a hard requirement is absent; True when skipped."""
        missing = sorted(key for key in info.requires if not ctx.artefacts.has(key))
        if not missing:
            return False
        blocked_by = self._provider_of(plan, missing[0])
        self._record(
            ctx,
            runs,
            StageRun(
                stage=info.name,
                outcome=StageOutcome.SKIPPED,
                skip_reason="dependency_missing",
                blocked_by=blocked_by,
            ),
        )
        ctx.events.publish(
            StageSkipped(
                scan_id=ctx.scan_id,
                stage=info.name,
                reason_code="dependency_missing",
                blocked_by=blocked_by,
            )
        )
        return True

    def _run_one(
        self, plan: RunPlan, ctx: RunContext, runs: list[StageRun], stage: Stage, index: int
    ) -> ScanStatus:
        """Run one stage and record it; returns the scan status afterwards."""
        info = plan.infos[stage.name]
        ctx.events.publish(
            StageStarted(scan_id=ctx.scan_id, stage=info.name, index=index, total=len(plan.order))
        )
        started_at = self._clock()
        clock_start = self._monotonic()
        error: Exception | None = None
        cancelled = False
        finished = False
        try:
            self._execute_stage(stage, info, ctx.for_stage(info.name))
            if any(not ctx.artefacts.has(key) for key in info.provides):
                raise _MissingProvidesError
            finished = True
        except ScanCancelledError:
            cancelled = True
        except Exception as caught:  # noqa: BLE001 - every stage failure is recorded
            error = caught
        finally:
            if not finished:
                self._discard_outputs(info, ctx)
        timing = _Timing(
            started_at=started_at,
            finished_at=self._clock(),
            duration_ms=max(0, int((self._monotonic() - clock_start) * 1000)),
        )
        if cancelled:
            self._record(ctx, runs, self._timed(info.name, StageOutcome.CANCELLED, timing))
            return ScanStatus.CANCELLED
        if error is not None:
            return self._failed(ctx, runs, info, error, timing)
        self._record(ctx, runs, self._timed(info.name, StageOutcome.SUCCEEDED, timing))
        _log.info(
            "stage_finished", stage=info.name, outcome="succeeded", duration_ms=timing.duration_ms
        )
        ctx.events.publish(
            StageFinished(
                scan_id=ctx.scan_id,
                stage=info.name,
                outcome="succeeded",
                duration_ms=timing.duration_ms,
            )
        )
        return ScanStatus.COMPLETED

    @staticmethod
    def _timed(
        name: str,
        outcome: StageOutcome,
        timing: _Timing,
        *,
        error_code: str | None = None,
        error_type: str | None = None,
    ) -> StageRun:
        return StageRun(
            stage=name,
            outcome=outcome,
            started_at=timing.started_at,
            finished_at=timing.finished_at,
            duration_ms=timing.duration_ms,
            error_code=error_code,
            error_type=error_type,
        )

    def _failed(
        self,
        ctx: RunContext,
        runs: list[StageRun],
        info: StageInfo,
        error: Exception,
        timing: _Timing,
    ) -> ScanStatus:
        """Record a failed stage; in this module every failure aborts the scan."""
        code = "missing_provides" if isinstance(error, _MissingProvidesError) else "stage_exception"
        error_type = error_type_of(error)
        self._record(
            ctx,
            runs,
            self._timed(
                info.name, StageOutcome.FAILED, timing, error_code=code, error_type=error_type
            ),
        )
        _log.error("stage_failed", stage=info.name, error_code=code, error_type=error_type)
        _log.debug("stage_failed_detail", stage=info.name, exc_info=error)
        ctx.events.publish(
            StageFailed(
                scan_id=ctx.scan_id,
                stage=info.name,
                policy="abort_scan",
                error_code=code,
                error_type=error_type,
                duration_ms=timing.duration_ms,
            )
        )
        return ScanStatus.FAILED

    def _mark_rest(
        self, plan: RunPlan, ctx: RunContext, runs: list[StageRun], status: ScanStatus
    ) -> ScanStatus:
        """Record stages that did not run: skipped after a failure, cancelled otherwise."""
        done = {run.stage for run in runs}
        for name in plan.order:
            if name in done:
                continue
            if status is ScanStatus.FAILED:
                self._record(
                    ctx,
                    runs,
                    StageRun(stage=name, outcome=StageOutcome.SKIPPED, skip_reason="scan_aborted"),
                )
                ctx.events.publish(
                    StageSkipped(scan_id=ctx.scan_id, stage=name, reason_code="scan_aborted")
                )
            else:
                status = ScanStatus.CANCELLED
                self._record(ctx, runs, StageRun(stage=name, outcome=StageOutcome.CANCELLED))
        return status

    def run(self, plan: RunPlan, ctx: RunContext) -> PipelineResult:
        """Execute ``plan``; raises only for a missing initial key or ``BaseException``."""
        for key in sorted(plan.initial_keys):
            if not ctx.artefacts.has(key):
                raise UnsatisfiedRequirementError(INITIAL, key)
        started_at = self._clock()
        scan_started = self._monotonic()
        ctx.budget.start()
        ctx.events.publish(ScanStarted(scan_id=ctx.scan_id, stage_count=len(plan.order)))
        ctx.events.publish(
            PlanResolved(
                scan_id=ctx.scan_id,
                stages=plan.order,
                wave_sizes=tuple(len(wave) for wave in plan.waves),
            )
        )
        runs: list[StageRun] = []
        status = ScanStatus.COMPLETED
        for index, stage in enumerate(plan.stages):
            if ctx.cancellation.is_cancelled:
                status = ScanStatus.CANCELLED
                break
            if self._skip_blocked(plan, ctx, runs, plan.infos[stage.name]):
                continue
            status = self._run_one(plan, ctx, runs, stage, index)
            if status is not ScanStatus.COMPLETED:
                break
        status = self._mark_rest(plan, ctx, runs, status)
        duration_ms = max(0, int((self._monotonic() - scan_started) * 1000))
        if status is ScanStatus.CANCELLED:
            completed = sum(1 for run in runs if run.outcome is StageOutcome.SUCCEEDED)
            ctx.events.publish(ScanCancelled(scan_id=ctx.scan_id, stages_completed=completed))
        else:
            ctx.events.publish(
                ScanFinished(scan_id=ctx.scan_id, status=status.value, duration_ms=duration_ms)
            )
        produced = sorted(
            {
                key
                for run in runs
                if run.outcome is StageOutcome.SUCCEEDED
                for key in plan.infos[run.stage].provides
            }
        )
        return PipelineResult(
            scan_id=ctx.scan_id,
            status=status,
            order=plan.order,
            waves=plan.waves,
            stage_runs=tuple(runs),
            produced_keys=tuple(produced),
            excluded=plan.excluded,
            started_at=started_at,
            finished_at=self._clock(),
        )
