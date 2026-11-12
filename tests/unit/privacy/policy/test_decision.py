"""PolicyDecision: one winner, path-free rule keys, explain text and the multi-file fold."""

import pytest

from codekavach.core.models.base import DataClassification
from codekavach.core.models.enums import PrivacyLevel
from codekavach.privacy.policy.decision import Contribution, DecisionAxis, PolicyDecision

H = "a" * 64
BASE = Contribution(DecisionAxis.BASE, "", PrivacyLevel.L3, "privacy.level")
PATH = Contribution(DecisionAxis.PATH_RULE, "0", PrivacyLevel.L4, "src/payments/**")
NEVER = Contribution(DecisionAxis.NEVER_SEND, "path_rule1", None, "**/secrets/**")


def decision(
    *parts: Contribution, never: bool = False, tags: tuple[str, ...] = ()
) -> PolicyDecision:
    levels = [p.level for p in parts if p.level is not None]
    return PolicyDecision(
        level=PrivacyLevel.strictest(*levels),
        never_send=never,
        classifications=tags,
        contributions=parts,
        policy_hash=H,
    )


def test_raw_classification() -> None:
    assert PolicyDecision.DATA_CLASSIFICATION is DataClassification.RAW


def test_winner_is_strictest_and_unique() -> None:
    d = decision(BASE, PATH)
    assert d.winner is PATH
    assert d.rule_key == "path_rule:0"


def test_never_send_wins_over_any_level() -> None:
    d = decision(BASE, PATH, NEVER, never=True)
    assert d.winner is NEVER
    assert "secrets" not in d.rule_key


def test_ties_go_to_the_first_contribution() -> None:
    other = Contribution(DecisionAxis.RULE, "0", PrivacyLevel.L3, "CWE-89")
    assert decision(BASE, other).winner is BASE


def test_rule_key_refuses_a_path_like_key() -> None:
    bad = Contribution(DecisionAxis.PATH_RULE, "src/x", PrivacyLevel.L4, "")
    with pytest.raises(ValueError, match="path-free"):
        _ = decision(bad).rule_key


def test_explain_marks_the_winner_and_says_never_sent() -> None:
    text = decision(BASE, PATH, NEVER, never=True).explain("src/secrets/k.py")
    assert text.splitlines()[0] == "src/secrets/k.py: -> never sent"
    marked = [line for line in text.splitlines() if line.startswith(" *")]
    assert len(marked) == 1
    assert "never_send" in marked[0]
    assert f"policy hash {H}" in text


def test_fold_is_strictest_and_counts_paths() -> None:
    folded = PolicyDecision.fold((decision(BASE), decision(BASE, PATH, tags=("pci",))))
    assert folded.level is PrivacyLevel.L4
    assert folded.paths == 2
    assert folded.classifications == ("pci",)
    assert not folded.never_send
    assert PolicyDecision.fold((decision(BASE), decision(BASE, NEVER, never=True))).never_send


def test_fold_of_nothing_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one"):
        PolicyDecision.fold(())
