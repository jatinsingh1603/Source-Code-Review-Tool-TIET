import tomllib
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings

from codekavach.config import Settings
from codekavach.config.errors import OrgPolicyError, ProjectTrustError
from codekavach.config.merge import deep_merge
from codekavach.config.orgpolicy.enforce import apply_additions, check_policy, locked_keys_of
from codekavach.config.orgpolicy.model import OrgPolicy
from codekavach.config.profiles import load_builtin_profile
from codekavach.core.models import PrivacyLevel
from tests.support.config import ConfigSandbox, to_toml
from tests.support.config_strategies import org_policies, settings_dicts

EXAMPLES = Path(__file__).resolve().parents[4] / "docs" / "examples"
DEFAULTS = Settings().model_dump(mode="json")
BASE = {"policy_version": 1, "organisation": "Example Bank Ltd"}
REMOTE = {"kind": "openai-compatible", "model": "m", "base_url": "https://llm.example.test/v1"}


def policy(**sections: Any) -> OrgPolicy:
    return OrgPolicy.model_validate({**BASE, **sections})


def data(**sections: Any) -> dict[str, Any]:
    return Settings.model_validate(deep_merge(DEFAULTS, sections)).model_dump(mode="json")


def rules(settings_data: dict[str, Any], rule_policy: OrgPolicy) -> list[str]:
    applied, _ = apply_additions(settings_data, rule_policy)
    return [violation.rule for violation in check_policy(applied, rule_policy)]


# one violating and one compliant case per rule row
CASES: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]] = [
    ({"privacy": {"min_level": "L3"}}, {"privacy": {"level": "L2"}}, {}, "privacy.min_level"),
    (
        {"privacy": {"min_level": "L3"}},
        {"privacy": {"paths": [{"pattern": "a/**", "level": "L1"}]}},
        {"privacy": {"paths": [{"pattern": "a/**", "level": "L4"}]}},
        "privacy.min_level",
    ),
    (
        {"privacy": {"min_level_by_tier": {"public": "L4"}}},
        {},
        {"privacy": {"provider_tier_levels": {"public": "L4"}}},
        "privacy.min_level_by_tier",
    ),
    (
        {"privacy": {"forbid_allowlist_extra": True}},
        {"privacy": {"public_allowlist_extra": ["Foo"]}},
        {},
        "privacy.forbid_allowlist_extra",
    ),
    ({"llm": {"allow_remote": False}}, {}, {"llm": {"allow_remote": False}}, "llm.allow_remote"),
    (
        {"llm": {"allowed_kinds": ["ollama"]}},
        {"llm": {"providers": {"x": REMOTE}}},
        {"llm": {"providers": {"x": {"kind": "ollama", "model": "m"}, "m": {"kind": "mock"}}}},
        "llm.allowed_kinds",
    ),
    (
        {"llm": {"allowed_providers": ["ok"]}},
        {"llm": {"providers": {"x": REMOTE}}},
        {"llm": {"providers": {"ok": REMOTE, "x": {**REMOTE, "enabled": False}}}},
        "llm.allowed_providers",
    ),
    (
        {"llm": {"allowed_base_url_hosts": ["llm.internal.example.test"]}},
        {"llm": {"providers": {"x": REMOTE}}},
        {
            "llm": {
                "providers": {
                    "x": {**REMOTE, "base_url": "https://LLM.internal.example.test/v1"},
                    "loop": {**REMOTE, "base_url": "http://127.0.0.1:8000/v1"},
                }
            }
        },
        "llm.allowed_base_url_hosts",
    ),
    (
        {"integrations": {"allow_github": False}},
        {"integrations": {"github": {"enabled": True, "repository": "o/r", "token": "env:GH"}}},
        {},
        "integrations.allow_github",
    ),
    (
        {"integrations": {"allowed_github_api_hosts": ["ghe.example.test"]}},
        {"integrations": {"github": {"enabled": True, "repository": "o/r", "token": "env:GH"}}},
        {
            "integrations": {
                "github": {
                    "enabled": True,
                    "repository": "o/r",
                    "token": "env:GH",
                    "api_url": "https://ghe.example.test/api/v3",
                }
            }
        },
        "integrations.allowed_github_api_hosts",
    ),
    (
        {"lock": {"reporting.include_privacy_attestation": True}},
        {"reporting": {"include_privacy_attestation": False}},
        {"reporting": {"include_privacy_attestation": True}},
        "lock",
    ),
]


@pytest.mark.parametrize(("sections", "bad", "good", "rule"), CASES, ids=[c[3] for c in CASES])
def test_rule_rows(
    sections: dict[str, Any], bad: dict[str, Any], good: dict[str, Any], rule: str
) -> None:
    rule_policy = policy(**sections)
    assert rules(data(**bad), rule_policy) == [rule]
    assert rules(data(**good), rule_policy) == []


def test_remote_provider_without_base_url() -> None:
    rule_policy = policy(llm={"allowed_base_url_hosts": ["llm.example.test"]})
    anthropic = data(llm={"providers": {"a": {"kind": "anthropic", "model": "m"}}})
    [violation] = check_policy(anthropic, rule_policy)
    assert "set base_url explicitly so that the host can be checked" in violation.message


def test_floor_and_never_send_are_additions() -> None:
    rule_policy = policy(privacy={"min_level": "L3", "never_send": ["**/hsm/**"]})
    applied, changed = apply_additions(DEFAULTS, rule_policy)
    assert changed == {"privacy.min_level", "privacy.never_send"}
    assert applied["privacy"]["min_level"] == "L3"
    assert applied["privacy"]["never_send"][-1] == "**/hsm/**"
    assert DEFAULTS["privacy"]["min_level"] == "L1"  # the input is not mutated
    assert check_policy(applied, rule_policy) == []


def test_locked_keys() -> None:
    rule_policy = policy(
        privacy={"min_level": "L3"},
        llm={"allow_remote": True},
        integrations={"allow_github": False},
        lock={"reporting.include_privacy_attestation": True},
    )
    assert locked_keys_of(rule_policy) == {
        "privacy.min_level",
        "llm.allow_remote",
        "integrations.github.enabled",
        "reporting.include_privacy_attestation",
    }


def test_example_policy_and_bank_strict_profile() -> None:
    text = (EXAMPLES / "policy.bank-strict.toml").read_text(encoding="utf-8")
    bank = OrgPolicy.model_validate(tomllib.loads(text))
    profile = data(**load_builtin_profile("bank-strict"))
    assert rules(profile, bank) == []


# loader


def test_user_file_below_floor(config_sandbox: ConfigSandbox) -> None:
    user = config_sandbox.write_user('[privacy]\nlevel = "L2"\n')
    policy_path = config_sandbox.write_policy(to_toml({**BASE, "privacy": {"min_level": "L3"}}))
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    [issue] = info.value.issues
    assert (issue.code.value, issue.source, issue.line) == ("CK-CFG-055", str(user), 2)
    assert issue.message == (
        "organisation policy 'Example Bank Ltd' requires privacy.level to be at least L3 "
        "(configured: L2)"
    )
    assert str(policy_path) in (issue.hint or "")


@pytest.mark.parametrize(
    ("kwargs", "env", "ok"),
    [
        ({"cli_overrides": {"privacy": {"level": "L1"}}}, {}, False),
        ({}, {"CODEKAVACH_PRIVACY__LEVEL": "L1"}, False),
        ({"cli_overrides": {"privacy": {"level": "L4"}}}, {}, True),
        ({"cli_overrides": {"llm": {"allow_remote": False}}}, {}, True),
    ],
)
def test_env_and_cli_cannot_go_below(
    config_sandbox: ConfigSandbox, kwargs: dict[str, Any], env: dict[str, str], ok: bool
) -> None:
    config_sandbox.write_policy(to_toml({**BASE, "privacy": {"min_level": "L3"}}))
    config_sandbox.env.update(env)
    if ok:
        config_sandbox.load(**kwargs)
        return
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load(**kwargs)
    assert info.value.issues[0].code.value == "CK-CFG-055"


def test_floor_origin_and_locked_keys(config_sandbox: ConfigSandbox) -> None:
    path = config_sandbox.write_policy(
        to_toml({**BASE, "privacy": {"min_level": "L3", "never_send": ["**/hsm/**"]}})
    )
    loaded = config_sandbox.load()
    assert loaded.settings.privacy.min_level is PrivacyLevel.L3
    origin = loaded.origins["privacy.min_level"]
    assert (origin.layer, origin.source) == ("org-policy", str(path))
    assert "**/hsm/**" in loaded.settings.privacy.never_send
    assert loaded.origins["privacy.never_send"].contributors[-1] == "org-policy"
    assert "privacy.min_level" in loaded.locked_keys


def test_allow_trust_false_overrides_every_trust_source(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_policy(to_toml({**BASE, "project_config": {"allow_trust": False}}))
    config_sandbox.write_project('[plugins]\ndisable = ["detector:secrets"]\n')
    config_sandbox.env["CODEKAVACH_TRUST_PROJECT_CONFIG"] = "1"
    for kwargs in ({}, {"trust_project_config": True}):
        with pytest.raises(ProjectTrustError) as info:
            config_sandbox.load(**kwargs)
        issue = info.value.issues[0]
        assert issue.code.value == "CK-CFG-040"
        assert "organisation policy forbids trusting project files" in (issue.hint or "")


def test_three_violations_in_one_exception(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(
        '[privacy]\nlevel = "L2"\npublic_allowlist_extra = ["Foo"]\n\n'
        "[reporting]\ninclude_privacy_attestation = false\n"
    )
    config_sandbox.write_policy(
        to_toml(
            {
                **BASE,
                "privacy": {"min_level": "L3", "forbid_allowlist_extra": True},
                "lock": {"reporting.include_privacy_attestation": True},
            }
        )
    )
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load()
    assert len(info.value.issues) == 3


def test_clamp_is_enforced_as_reject(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_policy(
        to_toml({**BASE, "enforcement": "clamp", "privacy": {"min_level": "L3"}})
    )
    loaded = config_sandbox.load()
    assert [w.code.value for w in loaded.warnings] == ["CK-CFG-055"]
    config_sandbox.write_user('[privacy]\nlevel = "L2"\n')
    with pytest.raises(OrgPolicyError):
        config_sandbox.load()


# properties


@given(settings_dicts(), org_policies())
@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
def test_accepted_settings_satisfy_the_policy(
    settings_data: dict[str, Any], policy_data: dict[str, Any]
) -> None:
    rule_policy = OrgPolicy.model_validate(policy_data)
    dumped = Settings.model_validate(settings_data).model_dump(mode="json")
    applied, _ = apply_additions(dumped, rule_policy)
    if check_policy(applied, rule_policy):
        return  # a load would raise 055
    try:
        final = Settings.model_validate(applied)
    except ValueError:
        return  # a load would raise a validation error
    assert check_policy(final.model_dump(mode="json"), rule_policy) == []
    floor = rule_policy.privacy.min_level
    if floor is not None:
        assert final.privacy.min_level.at_least(floor)
    assert set(rule_policy.privacy.never_send or []) <= set(final.privacy.never_send)


@given(settings_dicts(), org_policies())
@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
def test_additions_idempotent_and_only_tighten(
    settings_data: dict[str, Any], policy_data: dict[str, Any]
) -> None:
    rule_policy = OrgPolicy.model_validate(policy_data)
    dumped = Settings.model_validate(settings_data).model_dump(mode="json")
    once, _ = apply_additions(dumped, rule_policy)
    twice, changed = apply_additions(once, rule_policy)
    assert twice == once
    assert changed == set()
    before = PrivacyLevel(dumped["privacy"]["min_level"])
    assert PrivacyLevel(once["privacy"]["min_level"]).at_least(before)
    assert set(dumped["privacy"]["never_send"]) <= set(once["privacy"]["never_send"])
