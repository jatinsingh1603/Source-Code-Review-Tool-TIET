"""The ``privacy.vault.kms`` settings and the rules that guard the key-management source."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.errors import ConfigValidationError
from codekavach.config.validate import semantic_checks
from tests.support.config import ConfigSandbox

SECTION = (
    '[privacy.vault]\nkey_source = "kms"\n\n[privacy.vault.kms]\n'
    'endpoint = "https://kms.example.test"\nkey_id = "vault-key"\n'
    'token = "env:KMS_TOKEN"\nhost_allowlist = ["kms.example.test"]\n'
)


def codes(settings: Settings) -> list[str]:
    return [i.code.value for i in semantic_checks(settings, {}, project_root=Path("/work/repo"))]


def build(**section: Any) -> Settings:
    return Settings.model_validate({"privacy": {"vault": {"key_source": "kms", "kms": section}}})


def test_the_source_is_off_by_default_and_the_section_is_empty() -> None:
    settings = Settings()
    assert settings.privacy.vault.key_source == "keyring"
    kms = settings.privacy.vault.kms
    assert (kms.endpoint, kms.key_id, kms.token) == (None, None, None)
    assert kms.host_allowlist == []
    assert kms.timeout_seconds == 5.0


@pytest.mark.parametrize(
    "endpoint",
    ["http://kms.example.test", "ftp://kms.example.test", "kms.example.test", "https://"],
)
def test_the_endpoint_must_be_an_https_url(endpoint: str) -> None:
    with pytest.raises(ValidationError, match="CK-CFG-034"):
        build(endpoint=endpoint)


def test_the_endpoint_must_not_hold_credentials() -> None:
    with pytest.raises(ValidationError, match="credentials"):
        build(endpoint="https://user:pw@kms.example.test")  # pragma: allowlist secret


@pytest.mark.parametrize("seconds", [0.0, 0.4, 31.0])
def test_the_timeout_is_bounded(seconds: float) -> None:
    with pytest.raises(ValidationError):
        build(timeout_seconds=seconds)


def test_a_complete_section_passes_every_rule() -> None:
    settings = build(
        endpoint="https://kms.example.test",
        key_id="k",
        token="env:KMS_TOKEN",
        host_allowlist=["kms.example.test"],
    )
    assert codes(settings) == []


def test_missing_fields_are_reported_by_name() -> None:
    assert codes(build()) == ["CK-CFG-033", "CK-CFG-033", "CK-CFG-033"]


def test_a_host_outside_the_allow_list_is_a_configuration_error() -> None:
    settings = build(
        endpoint="https://kms.example.test",
        key_id="k",
        token="env:KMS_TOKEN",
        host_allowlist=["other.example.test"],
    )
    assert codes(settings) == ["CK-CFG-034"]


def test_an_empty_allow_list_is_a_configuration_error() -> None:
    settings = build(
        endpoint="https://kms.example.test",
        key_id="k",
        token="env:KMS_TOKEN",
    )
    assert codes(settings) == ["CK-CFG-034"]


def test_the_source_loads_outside_the_airgapped_profile(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(SECTION)
    loaded = config_sandbox.load()
    assert loaded.settings.privacy.vault.key_source == "kms"


def test_selecting_the_source_under_the_airgapped_profile_fails_at_load(
    config_sandbox: ConfigSandbox,
) -> None:
    config_sandbox.write_user(SECTION)
    with pytest.raises(ConfigValidationError) as raised:
        config_sandbox.load(profile="airgapped")
    found = [(i.code.value, i.key) for i in raised.value.issues]
    assert ("CK-CFG-036", "privacy.vault.key_source") in found


def test_the_airgapped_profile_still_loads_with_the_keyring(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[privacy.vault]\nkey_source = "keyring"\n')
    assert config_sandbox.load(profile="airgapped").settings.privacy.vault.key_source == "keyring"
