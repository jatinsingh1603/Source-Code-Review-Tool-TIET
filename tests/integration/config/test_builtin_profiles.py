"""The airgapped and bank-strict profiles resist contradiction (E03-24)."""

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings

from codekavach.config import ConfigError, Settings
from codekavach.config.errors import ConfigValidationError
from codekavach.config.profiles import load_builtin_profile
from tests.support.config import ConfigSandbox, isolate_config_env, to_toml
from tests.support.config_strategies import layer_sets

CLOUD = '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'


def codes(error: ConfigError) -> list[str]:
    return [issue.code.value for issue in error.issues]


def test_airgapped_rejects_remote_default(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(CLOUD)
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load(
            profile="airgapped", cli_overrides={"llm": {"default_provider": "primary"}}
        )
    assert "CK-CFG-031" in codes(info.value)


def test_airgapped_rejects_weaker_level(config_sandbox: ConfigSandbox) -> None:
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load(profile="airgapped", cli_overrides={"privacy": {"level": "L3"}})
    assert "CK-CFG-037" in codes(info.value)


def test_bank_strict_rejects_weaker_level(config_sandbox: ConfigSandbox) -> None:
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load(profile="bank-strict", cli_overrides={"privacy": {"level": "L2"}})
    assert "CK-CFG-037" in codes(info.value)


def test_bank_strict_never_send_is_a_union(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[privacy]\nnever_send = ["**/client-only/**"]\n')
    never_send = config_sandbox.load(profile="bank-strict").settings.privacy.never_send
    defaults = Settings().privacy.never_send
    profile_globs = load_builtin_profile("bank-strict")["privacy"]["never_send"]
    for glob in [*defaults, *profile_globs, "**/client-only/**"]:
        assert glob in never_send


def test_airgapped_disables_integrations(config_sandbox: ConfigSandbox) -> None:
    loaded = config_sandbox.load(profile="airgapped")
    assert not loaded.settings.integrations.github.enabled
    assert not loaded.settings.integrations.mcp.enabled
    assert not loaded.settings.llm.allow_remote


@given(layer_sets())
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_airgapped_never_selects_a_remote_default(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    layers: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    user, project = layers
    sandbox = ConfigSandbox(tmp_path_factory.mktemp("sandbox"))
    isolate_config_env(monkeypatch, sandbox.home)
    if user:
        sandbox.write_user(to_toml(user))
    if project:
        sandbox.write_project(to_toml(project))
    try:
        loaded = sandbox.load(profile="airgapped")
    except ConfigError:
        return  # a contradiction is reported, never resolved silently
    llm = loaded.settings.llm
    assert not llm.allow_remote
    chosen = llm.providers.get(llm.default_provider)
    assert chosen is None or not chosen.is_remote
