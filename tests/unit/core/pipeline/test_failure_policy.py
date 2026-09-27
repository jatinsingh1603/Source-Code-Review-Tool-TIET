from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.policy import RunState, decide_after_failure, skip_reason_for
from codekavach.core.pipeline.result import PipelineResult, StageOutcome, StageRun
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from tests.support.pipeline import CollectingBus, FakeStage, default_fake_stages, make_run_context

C = StageCategory
OK, FAILED, SKIPPED = StageOutcome.SUCCEEDED, StageOutcome.FAILED, StageOutcome.SKIPPED


def run(stages: list[FakeStage], failing: set[str]) -> tuple[PipelineResult, RunContext]:
    for stage in stages:
        if stage.name in failing:
            stage._raises = RuntimeError("boom")
    ctx = make_run_context()
    ctx.artefacts.put("scan.target", {"target": "repo"})
    return Orchestrator().run(plan_from_stages(stages), ctx), ctx


def outcomes(result: PipelineResult) -> dict[str, tuple[StageOutcome, str | None, str | None]]:
    return {r.stage: (r.outcome, r.skip_reason, r.blocked_by) for r in result.stage_runs}


def by_name(stages: list[FakeStage]) -> dict[str, FakeStage]:
    return {stage.name: stage for stage in stages}


def test_ingest_aborts() -> None:
    result, ctx = run(default_fake_stages(), {"ingest"})
    assert result.status is ScanStatus.FAILED
    rows = outcomes(result)
    assert rows["ingest"][0] is FAILED
    assert {rows[name] for name in rows if name != "ingest"} == {
        (SKIPPED, "scan_aborted", "ingest")
    }
    assert ctx.cancellation.reason == "aborted"


def test_analyse_taint_degrades() -> None:
    result, ctx = run(default_fake_stages(), {"analyse-taint"})
    assert result.status is ScanStatus.COMPLETED_WITH_ERRORS
    rows = outcomes(result)
    assert rows["analyse-taint"][0] is FAILED
    assert all(rows[name][0] is OK for name in rows if name != "analyse-taint")
    ref = ctx.artefacts.ref("candidates.raw")
    assert ref is not None
    assert [part for part, _ in ref.parts] == ["analyse-rules"]
    assert isinstance(ctx.events, CollectingBus)
    warnings = [event.to_dict() for event in ctx.events.of("warning")]
    assert {"stage": "aggregate", "code": "partial_input"}.items() <= warnings[0].items()


def test_parse_degrades() -> None:
    stages = default_fake_stages()
    stages.append(
        FakeStage("analyse-secrets", requires={"files"}, provides={"candidates.raw"},
                  category=C.ANALYSE, parts={"candidates.raw": []})
    )  # fmt: skip
    result, _ = run(stages, {"parse"})
    rows = outcomes(result)
    assert rows["analyse-rules"] == (SKIPPED, "dependency_failed", "parse")
    assert rows["analyse-taint"] == (SKIPPED, "dependency_failed", "parse")
    assert rows["analyse-secrets"][0] is OK
    for name in ("aggregate", "privacy-prepare", "llm-review", "restore", "rate", "report"):
        assert rows[name][0] is OK
    assert result.status is ScanStatus.COMPLETED_WITH_ERRORS


def test_privacy_prepare_fails_closed() -> None:
    stages = default_fake_stages()
    result, ctx = run(stages, {"privacy-prepare"})
    rows = outcomes(result)
    assert rows["privacy-prepare"][0] is FAILED
    assert rows["llm-review"] == (SKIPPED, "egress_locked", "privacy-prepare")
    assert rows["restore"] == (SKIPPED, "dependency_failed", "llm-review")
    for name in ("rate", "report", "sync"):
        assert rows[name][0] is OK
    assert by_name(stages)["llm-review"].calls == 0
    assert not ctx.artefacts.has("payloads.sanitised")
    assert ctx.artefacts.has("findings")
    assert result.egress_locked is True
    assert result.status is ScanStatus.COMPLETED_WITH_ERRORS


def test_llm_review_fails_closed() -> None:
    result, _ = run(default_fake_stages(), {"llm-review"})
    rows = outcomes(result)
    assert rows["restore"] == (SKIPPED, "dependency_failed", "llm-review")
    assert all(rows[name][0] is OK for name in ("rate", "report", "sync"))
    assert result.egress_locked is True


def test_uncategorised_stage_locks_egress() -> None:
    stages = default_fake_stages()
    stages.append(FakeStage("enrich", requires={"candidates"}, provides={"enrich.out"}))
    privacy = by_name(stages)["privacy-prepare"]
    privacy.optional_requires = frozenset({"enrich.out"})
    result, _ = run(stages, {"enrich"})
    rows = outcomes(result)
    assert rows["enrich"][0] is FAILED
    assert rows["privacy-prepare"] == (SKIPPED, "egress_locked", "enrich")
    assert rows["llm-review"] == (SKIPPED, "egress_locked", "enrich")
    assert rows["restore"] == (SKIPPED, "dependency_failed", "llm-review")
    assert all(rows[name][0] is OK for name in ("rate", "report", "sync"))
    assert result.status is ScanStatus.COMPLETED_WITH_ERRORS


def test_second_privacy_stage_is_locked_out() -> None:
    stages = default_fake_stages()
    stages.append(
        FakeStage("privacy-extra", requires={"candidates"}, provides={"privacy.extra"},
                  optional_requires={"payloads.sanitised"}, category=C.PRIVACY)
    )  # fmt: skip
    result, _ = run(stages, {"privacy-prepare"})
    assert outcomes(result)["privacy-extra"] == (SKIPPED, "egress_locked", "privacy-prepare")


def test_tightened_policy_aborts() -> None:
    stages = default_fake_stages()
    setattr(by_name(stages)["analyse-taint"], "failure_policy", FailurePolicy.ABORT_SCAN)  # noqa: B010
    result, _ = run(stages, {"analyse-taint"})
    assert result.status is ScanStatus.FAILED
    assert outcomes(result)["aggregate"] == (SKIPPED, "scan_aborted", "analyse-taint")


def test_skip_reason_precedence() -> None:
    stages = default_fake_stages()
    plan = plan_from_stages(stages)
    info = plan.infos["llm-review"]
    store = make_run_context().artefacts
    state = RunState()
    assert skip_reason_for(info, store, state, plan) == ("dependency_missing", None)
    state.skipped["privacy-prepare"] = StageRun("privacy-prepare", SKIPPED)
    assert skip_reason_for(info, store, state, plan) == ("dependency_failed", "privacy-prepare")
    decide_after_failure(plan.infos["privacy-prepare"], state)
    assert skip_reason_for(info, store, state, plan) == ("egress_locked", "privacy-prepare")
    decide_after_failure(describe_stage(FakeStage("ingest", provides={"x"},
                                                  category=C.INGEST)), state)  # fmt: skip
    assert skip_reason_for(info, store, state, plan) == ("scan_aborted", "ingest")


NAMES = [stage.name for stage in default_fake_stages()]
EGRESS = {C.PRIVACY, C.LLM, None}


@settings(max_examples=60, deadline=None)  # runs a whole fake pipeline per example
@given(st.sets(st.sampled_from(NAMES)))
def test_property_no_llm_after_privacy_failure(failing: set[str]) -> None:
    stages = default_fake_stages()
    result, _ = run(stages, failing)
    order = result.order
    fakes = by_name(stages)
    categories: dict[str, Any] = {stage.name: stage.category for stage in stages}
    llm = "llm-review"
    earlier = order[: order.index(llm)]
    if any(name in failing and categories[name] in EGRESS for name in earlier):
        assert fakes[llm].calls == 0
    aggregate = result.run_of("aggregate")
    if aggregate and aggregate.outcome is OK and result.status is not ScanStatus.FAILED:
        assert fakes["rate"].calls == 1


def test_completed_when_nothing_fails() -> None:
    result, _ = run(default_fake_stages(), set())
    assert result.status is ScanStatus.COMPLETED
    assert result.egress_locked is False


@pytest.mark.parametrize("failing", ["report", "sync", "rate"])
def test_late_degrade_failures(failing: str) -> None:
    result, _ = run(default_fake_stages(), {failing})
    assert result.status is ScanStatus.COMPLETED_WITH_ERRORS
    assert result.failed_stages() == (failing,)
