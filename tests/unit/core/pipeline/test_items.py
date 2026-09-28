import threading
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.budget import BudgetExceededError
from codekavach.core.pipeline.cancel import ScanCancelledError
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.items import (
    EGRESS_BLOCKED,
    ITEM_EXCEPTION,
    PRIVACY_PSEUDONYMISE_FAILED,
    ItemFailureLog,
    check_item,
    guard_item,
)
from codekavach.core.pipeline.keys import ITEM_FAILURES
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.scoped import StageRevokedError
from tests.support.pipeline import CollectingBus, FakeStage, default_fake_stages, make_run_context

CANDIDATE = "cand_01J8ZC3W6T5X0Q9V7R4M2N1K8P"  # pragma: allowlist secret


def stage_ctx(**kwargs: Any) -> RunContext:
    return make_run_context(**kwargs).for_stage("privacy-prepare")


# validation and ordering


@pytest.mark.parametrize("item_id", ["a/b", "has space", "", "x" * 65, "é"])
def test_bad_item_id_is_not_echoed(item_id: str) -> None:
    with pytest.raises(ValueError, match="item_id") as info:
        stage_ctx().fail_item(item_id, EGRESS_BLOCKED)
    if item_id:
        assert item_id not in str(info.value)


@pytest.mark.parametrize("code", ["Egress", "1bad", "a", "has-dash", "x" * 65])
def test_bad_error_code(code: str) -> None:
    with pytest.raises(ValueError, match="error_code"):
        check_item(CANDIDATE, code)


def test_snapshot_is_sorted() -> None:
    log = ItemFailureLog()
    log.add("restore", "pay_2", "restore_failed")
    log.add("privacy-prepare", "cand_b", EGRESS_BLOCKED)
    log.add("privacy-prepare", "cand_a", "policy_never_send")
    log.add("privacy-prepare", "cand_a", EGRESS_BLOCKED)
    assert [(f.stage, f.item_id, f.error_code) for f in log.snapshot()] == [
        ("privacy-prepare", "cand_a", EGRESS_BLOCKED),
        ("privacy-prepare", "cand_a", "policy_never_send"),
        ("privacy-prepare", "cand_b", EGRESS_BLOCKED),
        ("restore", "pay_2", "restore_failed"),
    ]


def test_thread_safety() -> None:
    log = ItemFailureLog()

    def record(worker: int) -> None:
        for index in range(100):
            log.add("s", f"cand_{worker:03d}_{index:03d}", ITEM_EXCEPTION)

    threads = [threading.Thread(target=record, args=(i,)) for i in range(100)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(log.snapshot()) == 10_000


def test_fail_item_needs_a_stage() -> None:
    with pytest.raises(RuntimeError):
        make_run_context().fail_item(CANDIDATE, EGRESS_BLOCKED)


def test_fail_item_publishes_one_event() -> None:
    bus = CollectingBus()
    ctx = stage_ctx(bus=bus)
    ctx.fail_item(CANDIDATE, EGRESS_BLOCKED)
    [event] = bus.of("item.failed")
    assert (event.stage, event.item_id, event.error_code) == (  # type: ignore[attr-defined]
        "privacy-prepare",
        CANDIDATE,
        EGRESS_BLOCKED,
    )
    assert len(ctx.item_failures.snapshot()) == 1


# guard_item


def explode(error: BaseException) -> None:
    raise error


def test_guard_swallows_ordinary_exceptions() -> None:
    ctx = stage_ctx()
    with guard_item(ctx, CANDIDATE, PRIVACY_PSEUDONYMISE_FAILED):
        explode(ValueError("secret-looking text that must not be stored"))
    [failure] = ctx.item_failures.snapshot()
    assert failure.error_code == PRIVACY_PSEUDONYMISE_FAILED
    assert "secret-looking" not in repr(failure)


@pytest.mark.parametrize(
    "error",
    [ScanCancelledError("user"), BudgetExceededError("llm.requests", 1), StageRevokedError("s")],
)
def test_guard_reraises_control_flow(error: BaseException) -> None:
    ctx = stage_ctx()
    with pytest.raises(type(error)), guard_item(ctx, CANDIDATE):
        raise error
    assert ctx.item_failures.snapshot() == ()


# orchestrator


class OneFailingPrivacyStage(FakeStage):
    """Prepares three candidates; the second fails and gets no payload."""

    def run(self, ctx: RunContext) -> None:
        payloads = []
        for item in ("cand_1", "cand_2", "cand_3"):
            with guard_item(ctx, item, PRIVACY_PSEUDONYMISE_FAILED):
                if item == "cand_2":
                    raise RuntimeError("could not pseudonymise")
                payloads.append({"candidate": item})
        ctx.artefacts.put("payloads.sanitised", payloads)


class CountingLlm(FakeStage):
    def run(self, ctx: RunContext) -> None:
        self.received = ctx.artefacts.get_json("payloads.sanitised")
        failures = ctx.artefacts.get_json(ITEM_FAILURES)
        self.failures_seen = failures
        super().run(ctx)


def test_item_failure_keeps_the_stage_and_scan_successful() -> None:
    stages = default_fake_stages()
    for index, stage in enumerate(stages):
        if stage.name == "privacy-prepare":
            stages[index] = OneFailingPrivacyStage(
                stage.name,
                requires=stage.requires,
                provides=stage.provides,
                optional_requires=stage.optional_requires,
                category=StageCategory.PRIVACY,
            )
        elif stage.name == "llm-review":
            stages[index] = CountingLlm(
                stage.name,
                requires=stage.requires,
                provides=stage.provides,
                optional_requires={ITEM_FAILURES},
                category=StageCategory.LLM,
            )
    llm = next(stage for stage in stages if stage.name == "llm-review")
    ctx = make_run_context()
    ctx.artefacts.put("scan.target", {"target": "repo"})
    result = Orchestrator().run(plan_from_stages(stages), ctx)
    assert result.status is ScanStatus.COMPLETED
    assert len(llm.received) == 2  # type: ignore[attr-defined]
    expected = [
        {"stage": "privacy-prepare", "item_id": "cand_2", "error_code": PRIVACY_PSEUDONYMISE_FAILED}
    ]
    assert llm.failures_seen == expected  # type: ignore[attr-defined]
    assert [(f.stage, f.item_id) for f in result.item_failures] == [("privacy-prepare", "cand_2")]
    assert ctx.artefacts.get_json(ITEM_FAILURES) == expected


def test_no_failures_gives_an_empty_list() -> None:
    ctx = make_run_context()
    ctx.artefacts.put("scan.target", {"target": "repo"})
    result = Orchestrator().run(plan_from_stages(default_fake_stages()), ctx)
    assert ctx.artefacts.get_json(ITEM_FAILURES) == []
    assert result.item_failures == ()


# property

_allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")


@given(st.text(min_size=1, max_size=40).filter(lambda text: any(c not in _allowed for c in text)))
def test_any_outside_character_is_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        check_item(text, EGRESS_BLOCKED)
