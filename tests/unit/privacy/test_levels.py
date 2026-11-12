"""Level plans and the consent / stage-plan rules (E25-02)."""

from pathlib import Path

import pytest

from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.levels import (
    LEVEL_PLANS,
    UNIT_BUDGET_FACTOR,
    level_available,
    llm_review_allowed,
    needs_reconsent,
    plan_for,
    render_level_table,
)


def test_every_level_has_a_plan() -> None:
    assert set(LEVEL_PLANS) == set(PrivacyLevel)


def test_l0_and_l4_send_no_code() -> None:
    for level in (PrivacyLevel.L0, PrivacyLevel.L4):
        assert not plan_for(level).sends_code
    assert all(plan_for(x).sends_code for x in (PrivacyLevel.L1, PrivacyLevel.L2, PrivacyLevel.L3))


def test_transformations_grow_with_level() -> None:
    assert plan_for(PrivacyLevel.L1).redact and not plan_for(PrivacyLevel.L1).pseudonymise
    assert plan_for(PrivacyLevel.L2).pseudonymise and plan_for(PrivacyLevel.L2).unit == "file"
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


def test_the_reference_table_is_generated_from_the_plans() -> None:
    reference = Path(__file__).parents[3] / "docs" / "reference" / "privacy-levels.md"
    text = reference.read_text(encoding="utf-8")
    start = text.index("<!-- generated from LEVEL_PLANS: do not edit by hand -->\n")
    end = text.index("<!-- end of generated table -->")
    table = text[start:end].split("\n", 1)[1]
    assert table == render_level_table()


def test_only_l1_retains_comments_and_whole_files_get_a_larger_budget() -> None:
    assert [lv for lv in PrivacyLevel if plan_for(lv).comments_retained] == [PrivacyLevel.L1]
    assert UNIT_BUDGET_FACTOR > 1
