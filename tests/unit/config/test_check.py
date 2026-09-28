from pathlib import Path
from typing import Any

import pytest

from codekavach.config import loader as loader_module
from codekavach.config.check import report_from_error, validate_configuration
from codekavach.config.errors import (
    ConfigError,
    ConfigErrorCode,
    ConfigIssue,
    ConfigSyntaxError,
    ConfigValidationError,
    OrgPolicyError,
    PlaintextSecretError,
    ProfileError,
    ProjectTrustError,
    SecretResolutionError,
)
from tests.support.config import ConfigSandbox

SUBCLASSES = [
    ConfigError,
    ConfigSyntaxError,
    ConfigValidationError,
    PlaintextSecretError,
    SecretResolutionError,
    ProfileError,
    ProjectTrustError,
    OrgPolicyError,
]


@pytest.mark.parametrize("cls", SUBCLASSES, ids=lambda c: c.__name__)
def test_every_config_error_gives_an_invalid_report(
    cls: type[ConfigError], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    warning = ConfigIssue(ConfigErrorCode.CK_CFG_038, "warning", "weak tier")
    error = cls([ConfigIssue(ConfigErrorCode.CK_CFG_003, "error", "bad value"), warning])

    def fail(**_: Any) -> None:
        raise error

    monkeypatch.setattr("codekavach.config.check.load_settings", fail)
    report = validate_configuration(target=tmp_path)
    assert not report.valid
    assert [i.code.value for i in report.errors] == ["CK-CFG-003"]
    assert report.warnings == (warning,)


def test_valid_report(config_sandbox: ConfigSandbox) -> None:
    project = config_sandbox.write_project('profile = "ci"\n')
    report = config_sandbox_report(config_sandbox)
    assert report.valid
    assert report.errors == ()
    assert report.profile == "ci"
    assert report.project_config == project


def config_sandbox_report(sandbox: ConfigSandbox, **kwargs: Any) -> Any:
    return validate_configuration(target=sandbox.root, env=sandbox.env, **kwargs)


def test_report_from_error_finds_project_file(config_sandbox: ConfigSandbox) -> None:
    project = config_sandbox.write_project("[scan]\njobs = 2\n")
    error = ConfigError([ConfigIssue(ConfigErrorCode.CK_CFG_061, "error", "bad --set")])
    report = report_from_error(error, target=config_sandbox.root)
    assert report.project_config == project
    assert report.to_dict()["project_config"] == str(project)


def test_unexpected_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, config_sandbox: ConfigSandbox
) -> None:
    def boom(**_: Any) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr("codekavach.config.check.load_settings", boom)
    with pytest.raises(RuntimeError):
        config_sandbox_report(config_sandbox)


def test_check_secrets_default_provider(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(
        '[llm]\ndefault_provider = "primary"\n\n'
        '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
    )
    missing = config_sandbox_report(config_sandbox, check_secrets=True)
    assert [i.code.value for i in missing.errors] == ["CK-CFG-012"]
    assert config_sandbox_report(config_sandbox).valid  # without the flag nothing resolves
    config_sandbox.env["ANTHROPIC_API_KEY"] = "a-set-value"  # pragma: allowlist secret
    assert config_sandbox_report(config_sandbox, check_secrets=True).valid


def test_check_secrets_skips_auto_and_mock(config_sandbox: ConfigSandbox) -> None:
    assert config_sandbox_report(config_sandbox, check_secrets=True).valid
    config_sandbox.write_user('[llm]\ndefault_provider = "mock"\n')
    assert config_sandbox_report(config_sandbox, check_secrets=True).valid


def test_check_secrets_github_token(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user('[integrations.github]\nenabled = true\nrepository = "o/r"\n')
    report = config_sandbox_report(config_sandbox, check_secrets=True)
    assert [(i.code.value, i.key) for i in report.errors] == [
        ("CK-CFG-012", "integrations.github.token")
    ]
    config_sandbox.env["GH_TOKEN"] = "a-set-value"  # pragma: allowlist secret
    assert config_sandbox_report(config_sandbox, check_secrets=True).valid


def test_loader_module_is_used() -> None:
    assert loader_module.load_settings is not None
