"""The privacy score: components, caps, monotonicity (E28-03)."""

from dataclasses import replace

from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.models import PrivacyLevel
from codekavach.privacy.attest import ScoreInputs, compute_privacy_score

BASE = ScoreInputs(
    payload_levels=(PrivacyLevel.L3, PrivacyLevel.L3),
    repo_pct=2.0,
    budget_ceiling_pct=100.0,
    residual_checked=True,
    residual_occurrences=0,
    tokens_total=10,
    tokens_shared=0,
    chain_ok=True,
)


def test_components_are_named_and_labelled() -> None:
    score = compute_privacy_score(BASE)
    kinds = {c.name: c.kind for c in score.components}
    assert kinds["level_strength"] == "indicative"
    assert kinds["disclosure_volume"] == "measured"
    assert kinds["naming_channel"] == "not_computed"
    assert kinds["budget_usage"] == "not_computed"
    assert 0 <= score.score <= 100


def test_nothing_sent_scores_full() -> None:
    empty = replace(BASE, payload_levels=(), repo_pct=0.0, tokens_total=0)
    assert compute_privacy_score(empty).score >= 95
    unlisted = compute_privacy_score(replace(empty, residual_checked=False))
    assert unlisted.score == 100
    assert unlisted.component("residual_terms").raw == "no payload to search"


def test_residual_term_caps_score() -> None:
    leaked = compute_privacy_score(replace(BASE, residual_occurrences=3))
    assert leaked.score <= 40
    assert any("residual" in c for c in leaked.caps)


def test_broken_chain_and_budget_cap() -> None:
    assert compute_privacy_score(replace(BASE, chain_ok=False)).score <= 50
    over = compute_privacy_score(replace(BASE, budget_ceiling_pct=1.0))
    assert over.score <= 60
    assert over.component("budget_usage").kind == "measured"


def test_weaker_level_scores_lower() -> None:
    weak = compute_privacy_score(replace(BASE, payload_levels=(PrivacyLevel.L1,)))
    assert weak.score < compute_privacy_score(BASE).score


@given(
    pct=st.floats(0, 100),
    shared=st.integers(0, 10),
    occ=st.integers(0, 5),
    level=st.sampled_from(list(PrivacyLevel)),
)
def test_score_is_bounded_and_monotone_in_disclosure(
    pct: float, shared: int, occ: int, level: PrivacyLevel
) -> None:
    a = replace(
        BASE, repo_pct=pct, tokens_shared=shared, residual_occurrences=occ, payload_levels=(level,)
    )
    b = replace(a, repo_pct=min(100.0, pct + 5))
    assert 0 <= compute_privacy_score(a).score <= 100
    assert compute_privacy_score(b).score <= compute_privacy_score(a).score
