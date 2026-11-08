"""A request refused only for the rate limit waits for the bucket instead of failing (E13-02b)."""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models.enums import EgressOutcome
from codekavach.privacy.egress.guard import EgressGuard, ScannerRegistry
from codekavach.privacy.egress.models import EgressMeta, LeakHit
from codekavach.privacy.egress.scanners import BudgetScanner
from codekavach.privacy.egress.session import EgressSession
from tests.support.factories import make_payload

RATE = 3
INTERVAL = 60.0 / RATE


class FakeTime:
    """One clock for the bucket and the sleeper, so a wait really refills the bucket."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@dataclass
class Reply:
    status: int = 200
    body: bytes = b"{}"


PAYLOAD = make_payload()


class Request:
    model = "m"
    body = json.dumps({"payload": PAYLOAD.text.expose()}).encode()


class Ledger:
    def __init__(self) -> None:
        self.outcomes: list[EgressOutcome] = []

    def append(self, draft: Any, payload: Any = None) -> Any:
        self.outcomes.append(draft.outcome)
        return type("Sealed", (), {"seq": len(self.outcomes)})()


class Fail:
    """A scanner that always refuses with one block code."""

    id = "fail"

    def __init__(self, code: str) -> None:
        self.code = code

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        return (LeakHit(scanner_id=self.id, block_code=self.code, count=1, first_offset=0),)


def session_with(*extra: Any, clock: FakeTime) -> tuple[EgressSession, Ledger]:
    settings = Settings.model_validate({"privacy": {"egress": {"rate_per_minute": RATE}}})
    budget = BudgetScanner(clock=clock.monotonic)
    budget.bind(None, settings)
    guard = EgressGuard(ScannerRegistry((budget, *extra)))
    session = EgressSession(
        settings=settings,
        state_dir=Path(),
        vault=None,  # type: ignore[arg-type]  # the scanners under test never read it
        scan_id="s",
        consent=None,
        sleep=clock.sleep,
        clock=clock.monotonic,
    )
    ledger = Ledger()
    session._guard = guard
    session._ledger = ledger  # type: ignore[assignment]
    session._transport = object()  # type: ignore[assignment]
    return session, ledger


def send(session: EgressSession, *, wait: float) -> Any:
    return session.dispatch(
        Request(),  # type: ignore[arg-type]
        provider="mock",
        model="m",
        task="triage",
        payload=PAYLOAD,
        respond=Reply,
        wait_seconds=wait,
    )


def test_a_request_past_the_rate_limit_waits_for_the_bucket_and_is_answered() -> None:
    clock = FakeTime()
    session, ledger = session_with(clock=clock)
    kinds = [send(session, wait=60.0).kind for _ in range(RATE + 2)]
    assert kinds == ["answered"] * (RATE + 2)
    assert clock.slept and all(0 < seconds <= INTERVAL for seconds in clock.slept)
    assert ledger.outcomes.count(EgressOutcome.BLOCKED) == 0


def test_without_a_wait_the_over_limit_request_is_blocked_once_and_ledgered() -> None:
    clock = FakeTime()
    session, ledger = session_with(clock=clock)
    kinds = [send(session, wait=0.0).kind for _ in range(RATE + 1)]
    assert kinds == ["answered"] * RATE + ["blocked"]
    assert clock.slept == []
    assert ledger.outcomes.count(EgressOutcome.BLOCKED) == 1


def test_a_wait_is_bounded_and_the_refusal_is_ledgered_once() -> None:
    clock = FakeTime()
    session, ledger = session_with(clock=clock)
    for _ in range(RATE):
        send(session, wait=0.0)
    clock.now += 0  # the bucket is empty and the clock is frozen: no wait can refill it
    frozen = FakeTime()
    frozen.now = clock.now
    session._sleep = frozen.slept.append  # time does not advance
    result = send(session, wait=3.0)
    assert result.kind == "blocked" and result.block_code == "rate_budget"
    assert sum(frozen.slept) == pytest.approx(3.0)
    assert ledger.outcomes.count(EgressOutcome.BLOCKED) == 1


def test_a_refusal_for_another_reason_is_final_and_never_waited_for() -> None:
    clock = FakeTime()
    session, ledger = session_with(Fail("residual_secret"), clock=clock)
    result = send(session, wait=60.0)
    assert result.kind == "blocked" and result.block_code == "residual_secret"
    assert clock.slept == []
    assert ledger.outcomes == [EgressOutcome.BLOCKED]
