"""Policy precedence (E13-02): never-send, then strictest of global, path rule and tier, floored."""

from typing import Any

import pytest

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel as L
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.policy.resolve import PolicyResolver

HOSTED = TrustTier.PUBLIC
LOCAL = TrustTier.LOCAL


def resolver(**privacy: Any) -> PolicyResolver:
    return PolicyResolver(Settings.model_validate({"privacy": privacy}))


WORKED = {
    "level": "L3",
    "min_level": "L2",
    "paths": [
        {"pattern": "services/api/fraud/**", "level": "L4"},
        {"pattern": "fixtures/seed/**", "never_send": True},
    ],
    "provider_tier_levels": {"public": "L3", "local": "L1"},
}


def test_the_worked_example_of_the_issue() -> None:
    policy = resolver(**WORKED)
    assert policy.effective_level("services/api/accounts.py", HOSTED) is L.L3
    assert policy.effective_level("services/api/fraud/rules.py", HOSTED) is L.L4
    assert policy.is_never_send("fixtures/seed/customers.json")
    assert not policy.is_never_send("services/api/accounts.py")


def test_a_local_tier_that_permits_l1_does_not_loosen_the_global_level() -> None:
    assert resolver(**WORKED).effective_level("services/api/accounts.py", LOCAL) is L.L3


def test_min_level_is_a_floor_not_a_target() -> None:
    policy = resolver(level="L2", min_level="L2", provider_tier_levels={"local": "L1"})
    assert policy.effective_level("a.py", LOCAL) is L.L2  # the tier would allow L1
    assert resolver(level="L3", min_level="L2").effective_level("a.py", LOCAL) is L.L3
    with pytest.raises(ValueError, match=r"weaker than privacy.min_level"):
        resolver(level="L1", min_level="L2")  # the configuration cannot go below the floor


def test_a_path_rule_can_only_tighten() -> None:
    policy = resolver(level="L3", paths=[{"pattern": "legacy/**", "level": "L1"}])
    assert policy.effective_level("legacy/x.py", HOSTED) is L.L3


def test_the_tier_level_can_tighten_the_global_level() -> None:
    policy = resolver(level="L1", min_level="L1", provider_tier_levels={"public": "L3"})
    assert policy.effective_level("a.py", HOSTED) is L.L3
    assert policy.effective_level("a.py", LOCAL) is L.L1


def test_l0_is_the_strictest_level_not_the_weakest() -> None:
    policy = resolver(level="L3", paths=[{"pattern": "vault/**", "level": "L0"}])
    assert policy.effective_level("vault/keys.py", HOSTED) is L.L0
    assert resolver(level="L0").effective_level("a.py", LOCAL) is L.L0


def test_the_most_specific_rule_wins_and_the_later_wins_a_tie() -> None:
    policy = resolver(
        level="L1",
        min_level="L1",
        provider_tier_levels={"public": "L1"},
        paths=[
            {"pattern": "src/**", "level": "L4"},
            {"pattern": "src/app/**", "level": "L2"},
            {"pattern": "docs/*.md", "level": "L2"},
            {"pattern": "docs/*.md", "level": "L3"},
        ],
    )
    assert policy.rule_level("src/app/x.py") is L.L2  # more literal segments than src/**
    assert policy.rule_level("src/other/x.py") is L.L4
    assert policy.rule_level("docs/a.md") is L.L3  # equal specificity: the later rule
    assert policy.rule_level("other/a.md") is None


def test_never_send_overrides_every_level_and_comes_from_both_settings() -> None:
    policy = resolver(
        never_send=["secrets_store"],
        paths=[
            {"pattern": "dump/**", "never_send": True},
            {"pattern": "dump/ok/**", "level": "L1"},
        ],
    )
    assert policy.is_never_send("secrets_store/a.txt")
    assert policy.is_never_send("app/secrets_store/a.txt")  # an unanchored name, at any depth
    assert policy.is_never_send("dump/ok/a.py")  # a level rule does not undo never-send
    assert not policy.is_never_send("app/other.py")


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("*.pem", "keys/a.pem", True),
        ("keys/*.pem", "keys/a.pem", True),
        ("keys/*.pem", "other/keys/a.pem", False),  # anchored
        ("keys/*.pem", "keys/deep/a.pem", False),  # * stays in one segment
        ("keys/**/*.pem", "keys/deep/er/a.pem", True),
        ("build", "pkg/build/out.py", True),  # a directory name matches everything below it
    ],
)
def test_glob_semantics(pattern: str, path: str, expected: bool) -> None:
    assert resolver(never_send=[pattern]).is_never_send(path) is expected


def test_every_level_combination_is_the_strictest_of_its_inputs() -> None:
    levels = [L.L1, L.L2, L.L3, L.L4, L.L0]
    for glob_level in levels:
        for rule_level in levels:
            for tier_level in levels:
                policy = resolver(
                    level=glob_level.value,
                    min_level="L1",
                    paths=[{"pattern": "a/**", "level": rule_level.value}],
                    provider_tier_levels={"public": tier_level.value},
                )
                expected = L.strictest(glob_level, rule_level, tier_level)
                assert policy.effective_level("a/x.py", HOSTED) is expected
