"""Organisation policy clamp mode and cumulative policies (E03-30)."""

from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings

from codekavach.config import Settings
from codekavach.config import paths as config_paths
from codekavach.config.errors import ConfigValidationError, OrgPolicyError
from codekavach.config.merge import deep_merge
from codekavach.config.orgpolicy.enforce import apply_policy, check_policy, clamp_policy
from codekavach.config.orgpolicy.model import OrgPolicy
from codekavach.core.models import PrivacyLevel
from tests.support.config import ConfigSandbox, to_toml
from tests.support.config_strategies import org_policies, settings_dicts

DEFAULTS = Settings().model_dump(mode="json")
BASE = {"policy_version": 1, "organisation": "Example Bank Ltd"}
REMOTE = {"kind": "openai-compatible", "model": "m", "base_url": "https://llm.example.test/v1"}
GITHUB = {"enabled": True, "repository": "examplebank/payments-api"}


def policy(mode: str = "clamp", **sections: Any) -> OrgPolicy:
    return OrgPolicy.model_validate({**BASE, "enforcement": mode, **sections})


def data(**sections: Any) -> dict[str, Any]:
    return Settings.model_validate(deep_merge(DEFAULTS, sections)).model_dump(mode="json")


# --- one test per clamp row --------------------------------------------------------------------

ROWS: dict[str, tuple[dict[str, Any], dict[str, Any], str, Any]] = {
    "min_level raises privacy.level": (
        {"privacy": {"min_level": "L3"}},
        {"privacy": {"level": "L2"}},
        "privacy.level",
        "L3",
    ),
    "min_level raises a path level": (
        {"privacy": {"min_level": "L3"}},
        {"privacy": {"paths": [{"pattern": "a/**", "level": "L1"}]}},
        "privacy.paths[0].level",
        "L3",
    ),
    "min_level_by_tier raises the tier level": (
        {"privacy": {"min_level_by_tier": {"public": "L4"}}},
        {},
        "privacy.provider_tier_levels.public",
        "L4",
    ),
    "forbid_allowlist_extra empties the list": (
        {"privacy": {"forbid_allowlist_extra": True}},
        {"privacy": {"public_allowlist_extra": ["Foo"]}},
        "privacy.public_allowlist_extra",
        [],
    ),
    "allow_remote false": (
        {"llm": {"allow_remote": False}},
        {"llm": {"allow_remote": True}},
        "llm.allow_remote",
        False,
    ),
    "allowed_kinds disables a provider": (
        {"llm": {"allowed_kinds": ["ollama"]}},
        {"llm": {"providers": {"remote": REMOTE}}},
        "llm.providers.remote.enabled",
        False,
    ),
    "allowed_providers disables a provider": (
        {"llm": {"allowed_providers": ["mock"]}},
        {"llm": {"providers": {"remote": REMOTE}}},
        "llm.providers.remote.enabled",
        False,
    ),
    "allowed_base_url_hosts disables a provider": (
        {"llm": {"allowed_base_url_hosts": ["llm.bank.test"]}},
        {"llm": {"providers": {"remote": REMOTE}}},
        "llm.providers.remote.enabled",
        False,
    ),
    "allow_github false disables the integration": (
        {"integrations": {"allow_github": False}},
        {"integrations": {"github": GITHUB}},
        "integrations.github.enabled",
        False,
    ),
    "lock sets the value": (
        {"lock": {"scan.jobs": 2}},
        {"scan": {"jobs": 8}},
        "scan.jobs",
        2,
    ),
}


def lookup(settings_data: dict[str, Any], key: str) -> Any:
    node: Any = settings_data
    for part in key.replace("[", ".").replace("]", "").split("."):
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


@pytest.mark.parametrize("name", sorted(ROWS))
def test_clamp_row(name: str) -> None:
    rule, configured, key, value = ROWS[name]
    rule_policy = policy(**rule)
    new, remaining, changed = apply_policy(data(**configured), rule_policy)
    assert remaining == []
    assert lookup(new, key) == value
    assert key in changed
    Settings.model_validate(new)  # still a valid configuration
    assert check_policy(new, rule_policy) == []
    reject = policy("reject", **rule)
    _, remaining_in_reject, _ = apply_policy(data(**configured), reject)
    assert remaining_in_reject, "reject mode reports what clamp mode fixes"


def test_default_provider_is_not_clampable() -> None:
    configured = data(llm={"providers": {"remote": REMOTE}, "default_provider": "remote"})
    for mode in ("clamp", "reject"):
        new, remaining, _ = apply_policy(
            configured, policy(mode, llm={"allowed_kinds": ["ollama"]})
        )
        assert [violation.rule for violation in remaining] == ["llm.allowed_kinds"]
        assert lookup(new, "llm.providers.remote.enabled") is True


def test_github_api_host_is_not_clampable() -> None:
    configured = data(integrations={"github": {**GITHUB, "api_url": "https://ghe.other.test/api"}})
    rule: dict[str, Any] = {"integrations": {"allowed_github_api_hosts": ["api.github.com"]}}
    _, remaining, _ = apply_policy(configured, policy(**rule))
    assert [violation.rule for violation in remaining] == ["integrations.allowed_github_api_hosts"]


def test_clamp_messages() -> None:
    outcome = clamp_policy(data(privacy={"level": "L2"}), policy(privacy={"min_level": "L3"}))
    (clamp,) = outcome.clamps
    from codekavach.config.orgpolicy.enforce import clamp_message  # noqa: PLC0415

    assert clamp_message(clamp) == (
        "organisation policy 'Example Bank Ltd' requires privacy.level to be at least L3; "
        "clamped to L3 (configured: L2)"
    )


# --- through the loader -----------------------------------------------------------------------


def test_example_clamps_with_one_warning(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_policy(
        to_toml({**BASE, "enforcement": "clamp", "privacy": {"min_level": "L3"}})
    )
    config_sandbox.write_user('[privacy]\nlevel = "L2"\n')
    loaded = config_sandbox.load()
    assert loaded.settings.privacy.level is PrivacyLevel.L3
    assert loaded.origins["privacy.level"].layer == "org-policy"
    (warning,) = loaded.warnings
    assert warning.code.value == "CK-CFG-055"
    assert warning.severity == "warning"
    assert warning.message.endswith("clamped to L3 (configured: L2)")
    assert warning.hint is not None and "policy file" in warning.hint


def test_disallowed_kind_is_disabled_under_clamp(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_policy(
        to_toml({**BASE, "enforcement": "clamp", "llm": {"allowed_kinds": ["ollama"]}})
    )
    config_sandbox.write_user(
        to_toml({"llm": {"allow_remote": True, "providers": {"remote": REMOTE}}})
    )
    loaded = config_sandbox.load()
    assert loaded.settings.llm.providers["remote"].enabled is False
    config_sandbox.write_user(
        to_toml(
            {
                "llm": {
                    "allow_remote": True,
                    "default_provider": "remote",
                    "providers": {"remote": REMOTE},
                }
            }
        )
    )
    with pytest.raises(OrgPolicyError):
        config_sandbox.load()


def system_policy(sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch, text: str) -> Path:
    path = sandbox.outside / "system-policy.toml"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(config_paths, "system_policy_paths", lambda: (path,))
    return path


@pytest.mark.parametrize(
    ("system_mode", "env_mode", "fails"),
    [
        ("clamp", "clamp", False),
        ("clamp", "reject", True),
        ("reject", "clamp", True),
        ("reject", "reject", True),
    ],
)
def test_mode_matrix(
    config_sandbox: ConfigSandbox,
    monkeypatch: pytest.MonkeyPatch,
    system_mode: str,
    env_mode: str,
    fails: bool,
) -> None:
    floor = {"privacy": {"min_level": "L3"}}
    system_policy(
        config_sandbox, monkeypatch, to_toml({**BASE, "enforcement": system_mode, **floor})
    )
    config_sandbox.write_policy(to_toml({**BASE, "enforcement": env_mode, **floor}))
    config_sandbox.write_user('[privacy]\nlevel = "L2"\n')
    if fails:
        with pytest.raises(OrgPolicyError):
            config_sandbox.load()
    else:
        assert config_sandbox.load().settings.privacy.level is PrivacyLevel.L3


def test_contradictory_locks_name_both_files(
    config_sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    system = system_policy(
        config_sandbox,
        monkeypatch,
        to_toml({**BASE, "enforcement": "clamp", "lock": {"scan.jobs": 2}}),
    )
    env = config_sandbox.write_policy(
        to_toml({**BASE, "enforcement": "clamp", "lock": {"scan.jobs": 4}})
    )
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    text = " ".join(f"{issue.source} {issue.hint}" for issue in info.value.issues)
    assert info.value.issues[0].code.value == "CK-CFG-055"
    assert str(system) in text
    assert str(env) in text


def test_floors_combine_to_the_strictest(
    config_sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_policy(
        config_sandbox,
        monkeypatch,
        to_toml({**BASE, "enforcement": "clamp", "privacy": {"min_level": "L3"}}),
    )
    config_sandbox.write_policy(
        to_toml({**BASE, "enforcement": "clamp", "privacy": {"min_level": "L2"}})
    )
    loaded = config_sandbox.load()
    assert loaded.settings.privacy.min_level is PrivacyLevel.L3


def test_clamping_to_l0_hits_the_semantic_checks(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_policy(
        to_toml({**BASE, "enforcement": "clamp", "privacy": {"min_level": "L0"}})
    )
    config_sandbox.write_user(
        to_toml(
            {
                "llm": {
                    "allow_remote": True,
                    "default_provider": "remote",
                    "providers": {"remote": REMOTE},
                }
            }
        )
    )
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load()
    assert "CK-CFG-032" in {issue.code.value for issue in info.value.issues}


# --- properties -------------------------------------------------------------------------------


def enabled_providers(settings_data: dict[str, Any]) -> set[str]:
    return {
        name
        for name, provider in settings_data["llm"]["providers"].items()
        if provider.get("enabled", True)
    }


@given(settings_dicts(), org_policies())
@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
def test_clamping_is_monotonic(settings_data: dict[str, Any], policy_data: dict[str, Any]) -> None:
    before = Settings.model_validate(settings_data).model_dump(mode="json")
    rule_policy = OrgPolicy.model_validate(policy_data)
    after, _, _ = apply_policy(before, rule_policy)

    def level(document: dict[str, Any]) -> PrivacyLevel:
        return PrivacyLevel(document["privacy"]["level"])

    assert level(after).at_least(level(before))
    assert PrivacyLevel(after["privacy"]["min_level"]).at_least(
        PrivacyLevel(before["privacy"]["min_level"])
    )
    for old_rule, new_rule in zip(
        before["privacy"]["paths"], after["privacy"]["paths"], strict=True
    ):
        if old_rule.get("level") and new_rule.get("level"):
            assert PrivacyLevel(new_rule["level"]).at_least(PrivacyLevel(old_rule["level"]))
    assert after["llm"]["allow_remote"] <= before["llm"]["allow_remote"]
    assert enabled_providers(after) <= enabled_providers(before)
    github = after["integrations"]["github"]["enabled"]
    assert github <= before["integrations"]["github"]["enabled"]
    assert set(before["privacy"]["never_send"]) <= set(after["privacy"]["never_send"])


@given(settings_dicts(), org_policies())
@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
def test_clamping_is_idempotent(settings_data: dict[str, Any], policy_data: dict[str, Any]) -> None:
    before = Settings.model_validate(settings_data).model_dump(mode="json")
    rule_policy = OrgPolicy.model_validate(policy_data)
    once, remaining, _ = apply_policy(before, rule_policy)
    twice, _, changed_again = apply_policy(once, rule_policy)
    assert twice == once
    assert changed_again == set()
    if rule_policy.enforcement == "clamp" and not remaining:
        assert check_policy(once, rule_policy) == []
