"""The guard suite bites: breaking a named privacy control makes its check fail (E28-03).

Each control has a ``check`` that returns True while the control holds. The test asserts that the
check passes on the real code and fails when the control is deliberately broken, so the suite's
sensitivity is demonstrated rather than assumed. ``test_mapping_is_complete`` asserts that every
control named in ``CONTROLS`` has a mutation.
"""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import TrustTier
from codekavach.privacy import levels
from codekavach.privacy.egress.aggregation import AggregationBudget, ExposureAccount
from codekavach.privacy.policy import engine as policy_engine
from codekavach.privacy.policy.engine import PolicyEngine, load_document
from tests.support.payload import segment, slice_of

_RealContribution = policy_engine.Contribution

POLICY = """
policy_version = 1
[[path]]
pattern = "**/secrets/**"
never_send = true
[[path]]
pattern = "pay/**"
level = "L4"
"""


def _engine() -> PolicyEngine:
    document, digest = load_document(POLICY)
    return PolicyEngine(Settings(), document, digest)


def check_never_send() -> bool:
    eng = _engine()
    return (
        eng.resolve("a/secrets/k.py", TrustTier.LOCAL).never_send
        and eng.resolve("deploy/server.pem", TrustTier.LOCAL).never_send
    )


def check_strictest_wins() -> bool:
    return _engine().resolve("pay/x.py", TrustTier.LOCAL).level is PrivacyLevel.L4


def check_budget_refuses() -> bool:
    account = ExposureAccount(100)
    account.record("s", "p", slice_of(segment("a.py", 1, ["x"] * 10)))
    other = slice_of(segment("b.py", 1, ["x"] * 10))
    return account.would_exceed(AggregationBudget(scan_pct=15.0), "s", "p", other)


def check_weaker_level_needs_consent() -> bool:
    return levels.needs_reconsent(PrivacyLevel.L3, PrivacyLevel.L1)


def check_l0_drops_remote_review() -> bool:
    return not levels.llm_review_allowed(PrivacyLevel.L0, TrustTier.PUBLIC)


@contextmanager
def _patch(target: Any, name: str, value: Any) -> Iterator[None]:
    original = getattr(target, name)
    setattr(target, name, value)
    try:
        yield
    finally:
        setattr(target, name, original)


def _NoNever(axis: str, key: str, level: Any, detail: str = "") -> Any:
    """A Contribution factory that turns every never_send into an ordinary L1 contribution."""
    if axis == "never_send":
        axis, level = "base", PrivacyLevel.L1
    return _RealContribution(axis, key, level, detail)  # type: ignore[arg-type]


def _break_never_send() -> Any:
    return _patch(policy_engine, "Contribution", _NoNever)


def _break_strictest() -> Any:
    return _patch(PrivacyLevel, "strictest", classmethod(lambda cls, *lv: min(lv)))


def _break_budget() -> Any:
    return _patch(ExposureAccount, "would_exceed", lambda *a, **k: False)


def _break_consent() -> Any:
    return _patch(levels, "needs_reconsent", lambda previous, requested: False)


def _break_l0() -> Any:
    return _patch(levels, "llm_review_allowed", lambda level, tier: True)


CONTROLS: dict[str, tuple[Callable[[], bool], Callable[[], Any]]] = {
    "policy.never_send": (check_never_send, _break_never_send),
    "policy.strictest_wins": (check_strictest_wins, _break_strictest),
    "egress.exposure_budget": (check_budget_refuses, _break_budget),
    "levels.reconsent": (check_weaker_level_needs_consent, _break_consent),
    "levels.l0_no_remote_review": (check_l0_drops_remote_review, _break_l0),
}


@pytest.mark.parametrize("name", sorted(CONTROLS))
def test_control_holds_and_its_check_notices_breakage(name: str) -> None:
    check, breaker = CONTROLS[name]
    assert check(), f"{name} must hold on the real code"
    with breaker():
        assert not check(), f"breaking {name} was not noticed by its check"
    assert check(), f"{name} must hold again after the mutation is undone"


def test_mapping_is_complete() -> None:
    assert set(CONTROLS) == {
        "policy.never_send",
        "policy.strictest_wins",
        "egress.exposure_budget",
        "levels.reconsent",
        "levels.l0_no_remote_review",
    }
    assert all(callable(c) and callable(b) for c, b in CONTROLS.values())
