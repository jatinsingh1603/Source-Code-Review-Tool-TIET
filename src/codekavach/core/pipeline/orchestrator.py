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

import dataclasses
import os
import queue
import re
import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from codekavach.core.log import get_logger
from codekavach.core.models import ScanStatus
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline.cache import (
    ConfigFingerprints,
    StageCache,
    StageCacheRecord,
    compute_stage_key,
    input_digests,
)
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
from codekavach.core.pipeline.execution import resolve_timeout, run_with_deadline
from codekavach.core.pipeline.keys import (
    ITEM_FAILURES,
    is_multi_provider,
    matches_stage_selector,
)
from codekavach.core.pipeline.manifest import collect_tool_versions
from codekavach.core.pipeline.plan import RunPlan
from codekavach.core.pipeline.policy import (
    LOCKED_CATEGORIES,
    RunState,
    decide_after_failure,
    partial_inputs,
    skip_reason_for,
)
from codekavach.core.pipeline.result import PipelineResult, StageOutcome, StageRun
from codekavach.core.pipeline.stage import FailurePolicy, Stage, StageInfo
from codekavach.core.store.base import ArtefactError, ArtefactRef
from codekavach.core.store.scoped import StageScopedStore, UndeclaredAccessError

INITIAL = "<initial>"
ABORTED = "aborted"
ERROR_SKIPS = frozenset({"dependency_failed", "egress_locked"})
ABANDONED_JOIN_SECONDS = 0.2
MAX_WORKERS = 32
_TOKEN_UNSAFE = re.compile(r"[^A-Za-z0-9_.:-]")
_log = get_logger("codekavach.pipeline")


def error_type_of(error: BaseException) -> str:
    """The exception's qualified class name, made safe for events (``<locals>`` and the like)."""
    name = _TOKEN_UNSAFE.sub("_", type(error).__qualname__)[:64]
    return name or "Exception"


class _MissingProvidesError(Exception):
    """Internal: a stage returned without writing one of its declared outputs."""


class _StageTimedOutError(Exception):
    """Internal: a stage did not finish within its effective timeout."""


@dataclass
class _Wave:
    """What happened while one wave ran; attribution waits until the wave has settled."""

    runs: dict[str, StageRun] = field(default_factory=dict)
    deferred: list[tuple[str, str]] = field(default_factory=list)
    abort_observed: bool = False
    lock_observed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


@dataclass(frozen=True, slots=True)
class _WaveOutcome:
    user_cancelled: bool


@dataclass(frozen=True, slots=True)
class _Scope:
    """The pieces of one ``Orchestrator.run`` call that every scheduled stage needs."""

    plan: RunPlan
    ctx: RunContext
    runs: list[StageRun]
    state: RunState


def max_workers(ctx: RunContext) -> int:
    """Stages of one wave that may run at once: ``scan.jobs``, or the CPU count, capped at 32."""
    return max(1, min(MAX_WORKERS, ctx.config.scan.jobs or (os.cpu_count() or 1)))


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
        cache: StageCache | None = None,
        use_cache: bool = True,
        refresh: Collection[str] = (),
        version: str = "0",
    ) -> None:
        self._clock = clock
        self._monotonic = monotonic
        self._cache = cache
        self._use_cache = use_cache
        self._refresh = tuple(refresh)
        self._version = version
        self._cache_lock = threading.Lock()
        self._stage_keys: dict[str, str] = {}
        self._fingerprints: ConfigFingerprints | None = None
        self._hits = 0
        self._misses = 0
        self._tool_versions: dict[str, dict[str, str]] = {}
        self._abandoned: list[tuple[str, threading.Thread]] = []
        self._abandoned_lock = threading.Lock()
        self._items_lock = threading.Lock()
        self._items_written = 0

    def _execute_stage(self, stage: Stage, info: StageInfo, stage_ctx: RunContext) -> None:
        """Run one stage on its scoped view (E04-17), under its effective timeout (E04-18).

        The stage runs in a dedicated daemon thread with a child cancellation token. On timeout
        the token is cancelled with reason ``timeout``, the view is revoked and the thread is
        abandoned; ``_StageTimedOut`` then lets ``_run_one`` record the stage as ``timed_out``.
        The view is revoked when the stage ends for any reason, so a lingering thread cannot write.
        """
        scoped = StageScopedStore(stage_ctx.artefacts, info)
        token = stage_ctx.cancellation.child()
        run_ctx = stage_ctx.for_stage(info.name, artefacts=scoped, cancellation=token)
        timeout = resolve_timeout(info, stage_ctx.config.scan, stage_ctx.remaining_seconds())
        try:
            result = run_with_deadline(
                lambda: stage.run(run_ctx), timeout, thread_name=f"ck-stage-{info.name}"
            )
            if result.outcome == "timed_out":
                token.cancel("timeout")
                scoped.revoke()
                with self._abandoned_lock:
                    self._abandoned.append((info.name, result.thread))
                raise _StageTimedOutError
            if result.error is not None:
                raise result.error
        finally:
            scoped.revoke()

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
        stage_key, cached = self._try_cache(plan, info, ctx, runs)
        if cached is not None:
            return cached
        ctx.events.publish(
            StageStarted(scan_id=ctx.scan_id, stage=info.name, index=index, total=len(plan.order))
        )
        started_at = self._clock()
        clock_start = self._monotonic()
        error: Exception | None = None
        cancelled = False
        finished = False
        timed_out = False
        try:
            self._execute_stage(stage, info, ctx.for_stage(info.name))
            self._collect_tool_versions(stage, info, ctx)
            if any(not ctx.artefacts.has(key) for key in info.provides):
                raise _MissingProvidesError
            finished = True
        except _StageTimedOutError:
            timed_out = True
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
        if timed_out:
            return self._failed(
                ctx=ctx,
                runs=runs,
                state=state,
                info=info,
                error=TimeoutError(),
                timing=timing,
                outcome=StageOutcome.TIMED_OUT,
                code="stage_timeout",
            )
        if cancelled:
            run = self._timed(info.name, StageOutcome.CANCELLED, timing)
            self._record(ctx, runs, run)
            return run
        if error is not None:
            return self._failed(
                ctx=ctx, runs=runs, state=state, info=info, error=error, timing=timing
            )
        run = dataclasses.replace(
            self._timed(info.name, StageOutcome.SUCCEEDED, timing), stage_key=stage_key
        )
        self._record(ctx, runs, run)
        if stage_key is not None and self._cache_writable(info):
            self._write_record(info, stage_key, ctx, timing.duration_ms)
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
            if isinstance(error, _MissingProvidesError):
                code = "missing_provides"
            elif isinstance(error, UndeclaredAccessError):
                code = "undeclared_access"
            else:
                code = "stage_exception"
        error_type = error_type_of(error)
        run = self._timed(info.name, outcome, timing, error_code=code, error_type=error_type)
        self._record(ctx, runs, run)
        with state.lock:
            state.failed[info.name] = run
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
        """Execute ``plan`` wave by wave; raises only for a missing initial key or BaseException.

        Stages of one wave are independent, so up to ``scan.jobs`` of them run at once (E04-19).
        Results do not depend on scheduling: skip decisions use the state at wave start, failure
        policies are applied after the wave has settled in ``plan.order``, and stage runs are
        reported in ``plan.order``.
        """
        started_at = self._clock()
        scan_started = self._monotonic()
        self._start(plan, ctx)
        runs: list[StageRun] = []
        state = RunState()
        user_cancelled = False
        with self._abandoned_lock:
            self._abandoned = []
        self._write_item_failures(ctx, force=True)
        with self._cache_lock:
            self._stage_keys = {}
            self._fingerprints = ConfigFingerprints(ctx.config)
            self._hits = self._misses = 0
            self._tool_versions = {}
        workers = max_workers(ctx)
        for wave in plan.waves:
            if self._stop_before(ctx, state, wave[0]):
                user_cancelled = True
                break
            runnable: list[str] = []
            for name in wave:
                info = plan.infos[name]
                reason = skip_reason_for(info, ctx.artefacts, state, plan)
                if reason is not None:
                    self._skip(ctx, runs, state, info, reason)
                else:
                    runnable.append(name)
            outcome = self._run_wave(_Scope(plan, ctx, runs, state), runnable, workers)
            if outcome.user_cancelled:
                user_cancelled = True
                break
        self._settle_abandoned(state)
        done = {run.stage for run in runs}
        for name in plan.order:
            if name not in done:
                self._record(ctx, runs, StageRun(stage=name, outcome=StageOutcome.CANCELLED))
        position = {name: index for index, name in enumerate(plan.order)}
        runs.sort(key=lambda run: position[run.stage])
        return self._finish(
            plan=plan,
            ctx=ctx,
            runs=runs,
            state=state,
            user_cancelled=user_cancelled,
            started_at=started_at,
            scan_started=scan_started,
        )

    def _stop_before(self, ctx: RunContext, state: RunState, stage: str) -> bool:
        """True when the run must stop before ``stage``: user cancel or exhausted scan budget."""
        self._check_deadline(ctx, stage)
        return self._user_cancelled(ctx, state)

    @staticmethod
    def _check_deadline(ctx: RunContext, stage: str) -> None:
        if ctx.budget.deadline_exceeded() and not ctx.cancellation.is_cancelled:
            ctx.cancellation.cancel("deadline")
            ctx.events.publish(
                WarningRaised(scan_id=ctx.scan_id, stage=stage, code="scan_deadline")
            )

    def _run_wave(self, scope: _Scope, runnable: list[str], workers: int) -> _WaveOutcome:
        """Run the runnable stages of one wave, at most ``workers`` at a time, then settle it."""
        wave = _Wave()
        pending = list(runnable)
        finished: queue.Queue[str] = queue.Queue()
        in_flight = 0
        while pending or in_flight:
            while pending and in_flight < workers:
                name = pending.pop(0)
                if not self._may_start(scope, wave, name):
                    continue
                if workers == 1 or len(runnable) == 1:
                    self._run_in_wave(scope, wave, name)
                    continue
                in_flight += 1
                threading.Thread(
                    target=self._run_and_signal,
                    args=(scope, wave, name, finished),
                    name=f"ck-wave-{name}",
                    daemon=True,
                ).start()
            if in_flight:
                finished.get()
                in_flight -= 1
        return self._settle_wave(scope, wave)

    def _may_start(self, scope: _Scope, wave: _Wave, name: str) -> bool:
        """Whether ``name`` may start now; defers the attribution of refused starts."""
        ctx = scope.ctx
        self._check_deadline(ctx, name)
        with wave.lock:
            if wave.abort_observed:
                wave.deferred.append((name, "scan_aborted"))
                return False
            if ctx.cancellation.is_cancelled:
                return False
            if wave.lock_observed and scope.plan.infos[name].category in LOCKED_CATEGORIES:
                wave.deferred.append((name, "egress_locked"))
                return False
        return True

    def _run_and_signal(
        self, scope: _Scope, wave: _Wave, name: str, finished: "queue.Queue[str]"
    ) -> None:
        try:
            self._run_in_wave(scope, wave, name)
        finally:
            finished.put(name)

    def _run_in_wave(self, scope: _Scope, wave: _Wave, name: str) -> None:
        plan = scope.plan
        info = plan.infos[name]
        run = self._run_one(
            plan=plan,
            ctx=scope.ctx,
            runs=scope.runs,
            state=scope.state,
            stage=plan.stage_by_name(name),
            index=plan.order.index(name),
        )
        self._write_item_failures(scope.ctx)
        failed = run.outcome in {StageOutcome.FAILED, StageOutcome.TIMED_OUT}
        with wave.lock:
            wave.runs[name] = run
            if failed and info.failure_policy is FailurePolicy.ABORT_SCAN:
                wave.abort_observed = True
            elif failed and info.failure_policy is FailurePolicy.FAIL_CLOSED:
                wave.lock_observed = True
        if failed and info.failure_policy is FailurePolicy.ABORT_SCAN:
            scope.ctx.cancellation.cancel(ABORTED)  # cooperative siblings stop early

    def _settle_wave(self, scope: _Scope, wave: _Wave) -> _WaveOutcome:
        """Apply the wave's failure policies in plan order, then record deferred skips."""
        plan, ctx, state = scope.plan, scope.ctx, scope.state
        for name in plan.order:
            run = wave.runs.get(name)
            if run is not None and run.outcome in {StageOutcome.FAILED, StageOutcome.TIMED_OUT}:
                decide_after_failure(plan.infos[name], state)
        if state.aborted:
            ctx.cancellation.cancel(ABORTED)
        position = {name: index for index, name in enumerate(plan.order)}
        for name, code in sorted(wave.deferred, key=lambda item: position[item[0]]):
            cause = state.abort_cause if code == "scan_aborted" else state.lock_cause
            self._skip(ctx, scope.runs, state, plan.infos[name], (code, cause))
        user_cancelled = not state.aborted and any(
            run.outcome is StageOutcome.CANCELLED for run in wave.runs.values()
        )
        return _WaveOutcome(user_cancelled=user_cancelled or self._user_cancelled(ctx, state))

    # stage cache (E04-21)

    def _stage_key(self, plan: RunPlan, info: StageInfo, ctx: RunContext) -> str | None:
        """Compute and remember the key of ``info`` (also for stages that are not cacheable)."""
        if self._cache is None:
            return None
        producers = {
            key: name for name, other in plan.infos.items() for key in other.transient_provides
        }
        with self._cache_lock:
            known = dict(self._stage_keys)
            fingerprints = self._fingerprints
        digests = input_digests(
            info, ctx.artefacts, transient_producers=producers, stage_keys=known
        )
        if digests is None or fingerprints is None:
            return None
        key = compute_stage_key(
            info,
            config_fp=fingerprints.of(info.config_sections),
            salt_fp=ctx.scan_salt.fingerprint() if info.salt_dependent else None,
            input_digests=digests,
        )
        with self._cache_lock:
            self._stage_keys[info.name] = key
        return key

    def _try_cache(
        self, plan: RunPlan, info: StageInfo, ctx: RunContext, runs: list[StageRun]
    ) -> tuple[str | None, StageRun | None]:
        """The stage key, and the ``cached`` run when the stage was served from the cache."""
        stage_key = self._stage_key(plan, info, ctx)
        if stage_key is None or not self._cache_eligible(info):
            return stage_key, None
        return stage_key, self._serve_from_cache(info, stage_key, ctx, runs)

    def _cache_writable(self, info: StageInfo) -> bool:
        return self._cache is not None and info.cacheable and not info.transient_provides

    def _cache_eligible(self, info: StageInfo) -> bool:
        refreshed = any(matches_stage_selector(info, selector) for selector in self._refresh)
        eligible = self._cache_writable(info) and self._use_cache and not refreshed
        if self._cache_writable(info) and not eligible:
            with self._cache_lock:
                self._misses += 1
        return eligible

    def _serve_from_cache(
        self, info: StageInfo, stage_key: str, ctx: RunContext, runs: list[StageRun]
    ) -> StageRun | None:
        """Bind the recorded outputs and record a ``cached`` run, or ``None`` on a miss."""
        assert self._cache is not None  # noqa: S101 - _cache_eligible checked it
        record = self._cache.lookup(stage_key)
        if record is None or set(record.outputs) != set(info.provides):
            with self._cache_lock:
                self._misses += 1
            return None
        try:
            for key, output in sorted(record.outputs.items()):
                parts = output.get("parts") or []
                if parts:
                    for part, digest in parts:
                        ctx.artefacts.bind_part(key, str(part), str(digest))
                else:
                    ref = ArtefactRef(key, str(output["digest"]), int(output["size"]))
                    ctx.artefacts.bind(key, ref)
        except (ArtefactError, KeyError, TypeError, ValueError):
            _log.warning("stage_cache_stale", stage=info.name)
            self._discard_outputs(info, ctx)
            self._cache.invalidate(stage_key)
            with self._cache_lock:
                self._misses += 1
            return None
        run = StageRun(
            stage=info.name, outcome=StageOutcome.CACHED, duration_ms=0, stage_key=stage_key
        )
        self._record(ctx, runs, run)
        with self._cache_lock:
            self._hits += 1
        _log.info("stage_finished", stage=info.name, outcome="cached", duration_ms=0)
        ctx.events.publish(
            StageFinished(scan_id=ctx.scan_id, stage=info.name, outcome="cached", duration_ms=0)
        )
        return run

    def _write_record(
        self, info: StageInfo, stage_key: str, ctx: RunContext, duration_ms: int
    ) -> None:
        """Record what a successful cacheable stage produced (digests, sizes, its own parts)."""
        assert self._cache is not None  # noqa: S101 - _cache_writable checked it
        outputs: dict[str, dict[str, Any]] = {}
        for key in sorted(info.provides):
            ref = ctx.artefacts.ref(key)
            if ref is None:
                return
            if is_multi_provider(key):
                own = [[part, digest] for part, digest in ref.parts if part == info.name]
                if not own:
                    return
                outputs[key] = {"digest": None, "size": None, "parts": own}
            elif ref.digest is None:
                return  # transient output: never cached
            else:
                outputs[key] = {"digest": ref.digest, "size": ref.size, "parts": []}
        record = StageCacheRecord(
            stage=info.name,
            stage_key=stage_key,
            outputs=outputs,
            created_at=self._clock().isoformat(),
            codekavach_version=self._version,
            duration_ms=duration_ms,
        )
        try:
            self._cache.store(record)
        except OSError:
            _log.warning("stage_cache_write_failed", stage=info.name)

    def _collect_tool_versions(self, stage: Stage, info: StageInfo, ctx: RunContext) -> None:
        """Record the stage's ``tool_versions()`` for the manifest (E04-24)."""
        versions, rejected = collect_tool_versions(stage)
        with self._cache_lock:
            self._tool_versions[info.name] = versions
        if rejected:
            ctx.events.publish(
                WarningRaised(scan_id=ctx.scan_id, stage=info.name, code="tool_versions_invalid")
            )

    def tool_versions(self) -> dict[str, dict[str, str]]:
        """Tool versions reported by the stages of the current or last run."""
        with self._cache_lock:
            return {name: dict(value) for name, value in self._tool_versions.items()}

    def _write_item_failures(self, ctx: RunContext, *, force: bool = False) -> None:
        """Refresh ``scan.item_failures`` in the inner store when stages added failures (E04-20).

        The orchestrator owns the key, so it is outside every stage's ``provides``; a consumer
        that lists it in ``optional_requires`` sees the failures of every earlier stage.
        """
        with self._items_lock:
            count = len(ctx.item_failures)
            if force or count != self._items_written:
                ctx.artefacts.put(ITEM_FAILURES, ctx.item_failures.to_json())
                self._items_written = count

    def _settle_abandoned(self, state: RunState) -> None:
        """Give abandoned stage threads a moment to end; warn about those still running."""
        with self._abandoned_lock:
            abandoned = list(self._abandoned)
        state.abandoned = [name for name, _ in abandoned]
        for _, thread in abandoned:
            thread.join(ABANDONED_JOIN_SECONDS)
        alive = sorted(name for name, thread in abandoned if thread.is_alive())
        if alive:
            _log.warning("stage_threads_still_running", stages=alive, count=len(alive))

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
                if run.outcome in {StageOutcome.SUCCEEDED, StageOutcome.CACHED}
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
            abandoned_threads=len(state.abandoned),
            item_failures=ctx.item_failures.snapshot(),
            cache_hits=self._hits,
            cache_misses=self._misses,
            tool_versions=self.tool_versions(),
            started_at=started_at,
            finished_at=self._clock(),
        )
