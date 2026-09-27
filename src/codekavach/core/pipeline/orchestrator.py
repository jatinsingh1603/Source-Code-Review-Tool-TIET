"""The orchestrator: runs a ``RunPlan`` stage by stage and applies the failure policies.

Owning epic: E04.

Per stage, in resolved order: stop if the user cancelled; skip the stage when the scan was aborted,
when egress is locked and the stage is a privacy, LLM or uncategorised one, or when a hard
requirement is absent (``codekavach.core.pipeline.policy``); run it through ``_execute_stage``;
check that every declared output was written; record a ``StageRun`` and publish events.

When a stage fails its outputs are discarded first (for a multi-provider key only its own part),
so nothing half-prepared can be consumed; then its failure policy decides whether the scan aborts,
continues, or continues with egress locked (I4). Deterministic stages keep running, so findings
from deterministic evidence are still reported.

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
    WarningRaised,
)
from codekavach.core.pipeline.keys import is_multi_provider
from codekavach.core.pipeline.plan import RunPlan
from codekavach.core.pipeline.policy import (
    RunState,
    decide_after_failure,
    partial_inputs,
    skip_reason_for,
)
from codekavach.core.pipeline.result import PipelineResult, StageOutcome, StageRun
from codekavach.core.pipeline.stage import Stage, StageInfo

INITIAL = "<initial>"
ABORTED = "aborted"
ERROR_SKIPS = frozenset({"dependency_failed", "egress_locked"})
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
    def _record(ctx: RunContext, runs: list[StageRun], run: StageRun) -> None:
        runs.append(run)
        ctx.run_log.append(run)

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

    def _skip(
        self,
        ctx: RunContext,
        runs: list[StageRun],
        state: RunState,
        info: StageInfo,
        reason: tuple[str, str | None],
    ) -> None:
        code, blocked_by = reason
        run = StageRun(
            stage=info.name, outcome=StageOutcome.SKIPPED, skip_reason=code, blocked_by=blocked_by
        )
        self._record(ctx, runs, run)
        with state.lock:
            state.skipped[info.name] = run
        ctx.events.publish(
            StageSkipped(
                scan_id=ctx.scan_id, stage=info.name, reason_code=code, blocked_by=blocked_by
            )
        )

    def _run_one(
        self,
        *,
        plan: RunPlan,
        ctx: RunContext,
        runs: list[StageRun],
        state: RunState,
        stage: Stage,
        index: int,
    ) -> StageRun:
        """Run one stage, record it and apply its failure policy; returns the recorded run."""
        info = plan.infos[stage.name]
        for _key in partial_inputs(info, state, plan):
            ctx.events.publish(
                WarningRaised(scan_id=ctx.scan_id, stage=info.name, code="partial_input")
            )
            break
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
            run = self._timed(info.name, StageOutcome.CANCELLED, timing)
            self._record(ctx, runs, run)
            return run
        if error is not None:
            return self._failed(
                ctx=ctx, runs=runs, state=state, info=info, error=error, timing=timing
            )
        run = self._timed(info.name, StageOutcome.SUCCEEDED, timing)
        self._record(ctx, runs, run)
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
        return run

    def _failed(
        self,
        *,
        ctx: RunContext,
        runs: list[StageRun],
        state: RunState,
        info: StageInfo,
        error: Exception,
        timing: _Timing,
        outcome: StageOutcome = StageOutcome.FAILED,
        code: str | None = None,
    ) -> StageRun:
        """Record a failed stage and apply its failure policy (outputs are already discarded)."""
        if code is None:
            missing = isinstance(error, _MissingProvidesError)
            code = "missing_provides" if missing else "stage_exception"
        error_type = error_type_of(error)
        run = self._timed(info.name, outcome, timing, error_code=code, error_type=error_type)
        self._record(ctx, runs, run)
        with state.lock:
            state.failed[info.name] = run
        decide_after_failure(info, state)
        if state.aborted:
            ctx.cancellation.cancel(ABORTED)
        _log.error("stage_failed", stage=info.name, error_code=code, error_type=error_type)
        _log.debug("stage_failed_detail", stage=info.name, exc_info=error)
        ctx.events.publish(
            StageFailed(
                scan_id=ctx.scan_id,
                stage=info.name,
                policy=info.failure_policy.value,
                error_code=code,
                error_type=error_type,
                duration_ms=timing.duration_ms,
            )
        )
        return run

    @staticmethod
    def _status(runs: list[StageRun], state: RunState, user_cancelled: bool) -> ScanStatus:
        if state.aborted:
            return ScanStatus.FAILED
        if user_cancelled:
            return ScanStatus.CANCELLED
        for run in runs:
            if run.outcome in {StageOutcome.FAILED, StageOutcome.TIMED_OUT}:
                return ScanStatus.COMPLETED_WITH_ERRORS
            if run.outcome is StageOutcome.SKIPPED and run.skip_reason in ERROR_SKIPS:
                return ScanStatus.COMPLETED_WITH_ERRORS
        return ScanStatus.COMPLETED

    def _start(self, plan: RunPlan, ctx: RunContext) -> None:
        for key in sorted(plan.initial_keys):
            if not ctx.artefacts.has(key):
                raise UnsatisfiedRequirementError(INITIAL, key)
        ctx.budget.start()
        ctx.events.publish(ScanStarted(scan_id=ctx.scan_id, stage_count=len(plan.order)))
        ctx.events.publish(
            PlanResolved(
                scan_id=ctx.scan_id,
                stages=plan.order,
                wave_sizes=tuple(len(wave) for wave in plan.waves),
            )
        )

    def _user_cancelled(self, ctx: RunContext, state: RunState) -> bool:
        return ctx.cancellation.is_cancelled and not state.aborted

    def run(self, plan: RunPlan, ctx: RunContext) -> PipelineResult:
        """Execute ``plan``; raises only for a missing initial key or ``BaseException``."""
        started_at = self._clock()
        scan_started = self._monotonic()
        self._start(plan, ctx)
        runs: list[StageRun] = []
        state = RunState()
        user_cancelled = False
        for index, stage in enumerate(plan.stages):
            info = plan.infos[stage.name]
            if self._user_cancelled(ctx, state):
                user_cancelled = True
                break
            reason = skip_reason_for(info, ctx.artefacts, state, plan)
            if reason is not None:
                self._skip(ctx, runs, state, info, reason)
                continue
            run = self._run_one(
                plan=plan, ctx=ctx, runs=runs, state=state, stage=stage, index=index
            )
            if run.outcome is StageOutcome.CANCELLED and not state.aborted:
                user_cancelled = True
                break
        done = {run.stage for run in runs}
        for name in plan.order:
            if name not in done:
                self._record(ctx, runs, StageRun(stage=name, outcome=StageOutcome.CANCELLED))
        return self._finish(
            plan=plan,
            ctx=ctx,
            runs=runs,
            state=state,
            user_cancelled=user_cancelled,
            started_at=started_at,
            scan_started=scan_started,
        )

    def _finish(
        self,
        *,
        plan: RunPlan,
        ctx: RunContext,
        runs: list[StageRun],
        state: RunState,
        user_cancelled: bool,
        started_at: datetime,
        scan_started: float,
    ) -> PipelineResult:
        status = self._status(runs, state, user_cancelled)
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
            egress_locked=state.egress_locked,
            started_at=started_at,
            finished_at=self._clock(),
        )
