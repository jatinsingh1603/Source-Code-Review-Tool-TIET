"""Level plans and the consent / stage-plan rules (E25-02)."""

import pytest

from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.levels import (
    LEVEL_PLANS,
    level_available,
    llm_review_allowed,
    needs_reconsent,
    plan_for,
)


def test_every_level_has_a_plan() -> None:
    assert set(LEVEL_PLANS) == set(PrivacyLevel)


def test_l0_and_l4_send_no_code() -> None:
    for level in (PrivacyLevel.L0, PrivacyLevel.L4):
        assert not plan_for(level).sends_code
    assert all(plan_for(x).sends_code for x in (PrivacyLevel.L1, PrivacyLevel.L2, PrivacyLevel.L3))


def test_transformations_grow_with_level() -> None:
    assert plan_for(PrivacyLevel.L1).redact and not plan_for(PrivacyLevel.L1).pseudonymise
    assert plan_for(PrivacyLevel.L2).pseudonymise and plan_for(PrivacyLevel.L2).unit == "function"
    assert plan_for(PrivacyLevel.L3).slice_ and plan_for(PrivacyLevel.L3).unit == "slice"


def test_l4_fails_closed() -> None:
    assert not level_available(PrivacyLevel.L4)
    assert level_available(PrivacyLevel.L3)


@pytest.mark.parametrize("tier", [TrustTier.PRIVATE, TrustTier.PUBLIC])
def test_l0_drops_review_for_non_local(tier: TrustTier) -> None:
    assert not llm_review_allowed(PrivacyLevel.L0, tier)
    assert llm_review_allowed(PrivacyLevel.L0, TrustTier.LOCAL)
    assert llm_review_allowed(PrivacyLevel.L3, tier)


def test_reconsent_when_weaker() -> None:
    assert needs_reconsent(None, PrivacyLevel.L3)
    assert needs_reconsent(PrivacyLevel.L3, PrivacyLevel.L1)
    assert not needs_reconsent(PrivacyLevel.L1, PrivacyLevel.L3)
    assert not needs_reconsent(PrivacyLevel.L3, PrivacyLevel.L0)
