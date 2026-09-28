import random
import threading
import time
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.events import WarningRaised
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import RunPlan, plan_from_stages
from codekavach.core.pipeline.result import PipelineResult, StageOutcome
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory
from tests.support.pipeline import CollectingBus, FakeStage, default_fake_stages, make_run_context

C = StageCategory
# Planted failures log a DEBUG traceback; JSON into a buffer keeps that cheap.
pytestmark = pytest.mark.usefixtures("log_output")


def settings(jobs: int) -> Settings:
    return Settings.model_validate({"scan": {"jobs": jobs}})


def run(stages: list[FakeStage], jobs: int, **kwargs: Any) -> tuple[PipelineResult, RunContext]:
    ctx = make_run_context(settings=settings(jobs), **kwargs)
    ctx.artefacts.put("scan.target", {"target": "repo"})
    return Orchestrator().run(plan_from_stages(stages), ctx), ctx


def siblings(count: int, **kwargs: Any) -> list[FakeStage]:
    return [
        FakeStage(
            f"analyse-{i}",
            requires={"scan.target"},
            provides={f"k{i}"},
            category=C.ANALYSE,
            **kwargs,
        )
        for i in range(count)
    ]


class Counting(FakeStage):
    """Records the maximum number of stages running at the same time."""

    active = 0
    peak = 0
    lock = threading.Lock()

    def run(self, ctx: RunContext) -> None:
        with Counting.lock:
            Counting.active += 1
            Counting.peak = max(Counting.peak, Counting.active)
        try:
            time.sleep(0.05)
            super().run(ctx)
        finally:
            with Counting.lock:
                Counting.active -= 1


def test_scheduler_respects_max_workers() -> None:
    Counting.active = Counting.peak = 0
    stages: list[FakeStage] = [
        Counting(f"analyse-{i}", requires={"scan.target"}, provides={f"k{i}"}, category=C.ANALYSE)
        for i in range(6)
    ]
    result, _ = run(stages, jobs=2)
    assert result.status is ScanStatus.COMPLETED
    assert Counting.peak == 2


def test_timing_bounds() -> None:
    started = time.monotonic()
    run(siblings(3, sleep_seconds=0.15), jobs=3)
    parallel = time.monotonic() - started
    started = time.monotonic()
    run(siblings(3, sleep_seconds=0.15), jobs=1)
    sequential = time.monotonic() - started
    assert parallel < 0.4
    assert sequential >= 0.45


def fingerprint(result: PipelineResult, ctx: RunContext) -> tuple[Any, ...]:
    digests = {}
    for key in result.produced_keys:
        ref = ctx.artefacts.ref(key)
        digests[key] = (ref.digest, ref.parts) if ref else None
    runs = [
        (r.stage, r.outcome, r.error_code, r.skip_reason, r.blocked_by) for r in result.stage_runs
    ]
    return result.status, tuple(sorted(digests.items())), tuple(runs)


def test_deterministic_over_thirty_runs() -> None:
    rng = random.Random(1603)  # noqa: S311 - reproducible scheduling noise
    seen = set()
    for _ in range(30):
        stages = default_fake_stages()
        for stage in stages:
            stage._sleep_seconds = rng.uniform(0, 0.01)
        result, ctx = run(stages, jobs=8)
        seen.add(fingerprint(result, ctx))
    assert len(seen) == 1


def failing_wave(rng: random.Random) -> list[FakeStage]:
    first = FakeStage(
        "analyse-a", requires={"scan.target"}, provides={"a.one"}, category=C.ANALYSE,
        raises=RuntimeError("a"), sleep_seconds=rng.uniform(0, 0.02),
    )  # fmt: skip
    second = FakeStage(
        "analyse-b", requires={"scan.target"}, provides={"a.two"}, category=C.ANALYSE,
        raises=RuntimeError("b"), sleep_seconds=rng.uniform(0, 0.02),
    )  # fmt: skip
    consumer = FakeStage(
        "aggregate", requires={"a.one", "a.two"}, provides={"candidates"}, category=C.AGGREGATE
    )
    return [second, first, consumer]


def test_failure_attribution_is_deterministic() -> None:
    rng = random.Random(7)  # noqa: S311 - reproducible scheduling noise
    for _ in range(30):
        result, _ = run(failing_wave(rng), jobs=8)
        consumer = result.run_of("aggregate")
        assert consumer is not None
        assert (consumer.skip_reason, consumer.blocked_by) == ("dependency_failed", "analyse-a")
        assert [r.stage for r in result.stage_runs] == ["analyse-a", "analyse-b", "aggregate"]


def test_abort_in_a_wave_cancels_cooperative_sibling() -> None:
    aborting = FakeStage(
        "analyse-a", requires={"scan.target"}, provides={"a.one"}, category=C.ANALYSE,
        raises=RuntimeError("boom"), failure_policy=FailurePolicy.ABORT_SCAN,
    )  # fmt: skip
    sleeper = FakeStage(
        "analyse-b", requires={"scan.target"}, provides={"a.two"}, category=C.ANALYSE,
        sleep_seconds=2.0,
    )  # fmt: skip
    started = time.monotonic()
    result, _ = run([aborting, sleeper], jobs=2)
    assert time.monotonic() - started < 0.3 + 0.2
    assert result.status is ScanStatus.FAILED
    sibling = result.run_of("analyse-b")
    assert sibling is not None
    assert sibling.outcome is StageOutcome.CANCELLED


def test_fail_closed_in_a_wave_skips_unstarted_llm_stage() -> None:
    stages = default_fake_stages()
    by_name = {stage.name: stage for stage in stages}
    llm = by_name["llm-review"]
    closer = FakeStage(
        "analyse-sidecar", requires=set(llm.requires), provides={"sidecar.out"},
        category=C.ANALYSE, raises=RuntimeError("x"), failure_policy=FailurePolicy.FAIL_CLOSED,
    )  # fmt: skip
    plan = plan_from_stages([*stages, closer])
    wave = next(w for w in plan.waves if "llm-review" in w)
    assert "analyse-sidecar" in wave
    assert wave.index("analyse-sidecar") < wave.index("llm-review")
    ctx = make_run_context(settings=settings(1))
    ctx.artefacts.put("scan.target", {"target": "repo"})
    result = Orchestrator().run(plan, ctx)
    skipped = result.run_of("llm-review")
    assert skipped is not None
    assert (skipped.outcome, skipped.skip_reason, skipped.blocked_by) == (
        StageOutcome.SKIPPED,
        "egress_locked",
        "analyse-sidecar",
    )
    assert llm.calls == 0
    assert result.egress_locked


class Charging(FakeStage):
    def run(self, ctx: RunContext) -> None:
        for _ in range(100):
            ctx.budget.charge("units", 1)
            ctx.events.publish(WarningRaised(scan_id=ctx.scan_id, stage=self.name, code="tick"))
        super().run(ctx)


def test_shared_objects_stay_consistent() -> None:
    bus = CollectingBus()
    stages: list[FakeStage] = [
        Charging(f"analyse-{i}", requires={"scan.target"}, provides={f"k{i}"}, category=C.ANALYSE)
        for i in range(8)
    ]
    result, ctx = run(stages, jobs=8, bus=bus)
    assert result.status is ScanStatus.COMPLETED
    assert ctx.budget.used("units") == 800
    assert len([e for e in bus.of("warning") if getattr(e, "code", None) == "tick"]) == 800
    assert len(ctx.run_log.snapshot()) == 8


def test_plan_type_is_kept() -> None:
    assert isinstance(plan_from_stages(siblings(2)), RunPlan)
