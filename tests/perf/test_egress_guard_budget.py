"""Performance budget of the egress guard on a 256 KB body (E12-01).

The issue gives two budgets: the guard's own work outside the scanners stays under 1 ms, and a
whole ``evaluate`` stays under 50 ms. The scanners arrive in E12-02, so six that return at once
stand in for them here and E12-02 re-measures the 50 ms with the real ones. The bodies are built
to be the worst case the guard's own checks can meet: the payload is the whole body, and it must
be hashed and then found. Both budgets are scaled by the performance factor.
"""

from collections.abc import Sequence

import pytest

from codekavach.config import Settings
from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.enums import PrivacyLevel
from codekavach.privacy.egress.guard import EgressGuard, LeakHit, ScannerRegistry
from codekavach.privacy.egress.models import EgressMeta
from tests.support.perf import assert_within_budget, measure

BODY_BYTES = 262_144
OWN_BUDGET_SECONDS = 0.001
WHOLE_BUDGET_SECONDS = 0.050
PAYLOAD = "x = 1\n" * (BODY_BYTES // 6)
BODY = PAYLOAD.encode("utf-8")
META = EgressMeta(
    provider="mock", model="m", level=PrivacyLevel.L3, payload_hash=sha256_hex(PAYLOAD)
)
SETTINGS = Settings.model_validate({"llm": {"providers": {"mock": {"kind": "mock"}}}})


class Instant:
    """A scanner that costs nothing, so what is measured is the guard."""

    def __init__(self, scanner_id: str) -> None:
        self.id = scanner_id

    def scan(self, body: bytes, meta: EgressMeta) -> Sequence[LeakHit]:
        return ()


def guard_with(count: int) -> EgressGuard:
    return EgressGuard(ScannerRegistry([Instant(f"s{index}") for index in range(count)]))


def evaluate(guard: EgressGuard) -> None:
    decision = guard.evaluate(BODY, META, settings=SETTINGS, consent=None, payload_text=PAYLOAD)
    assert decision.allowed


@pytest.mark.perf
def test_evaluate_on_a_256_kb_body_stays_within_budget() -> None:
    guard = guard_with(6)
    assert_within_budget(measure(lambda: evaluate(guard), repeat=20), WHOLE_BUDGET_SECONDS)


@pytest.mark.perf
def test_the_guards_own_work_stays_within_budget() -> None:
    guard = guard_with(1)
    assert_within_budget(measure(lambda: evaluate(guard), repeat=50), OWN_BUDGET_SECONDS)
