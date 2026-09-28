"""Semantic issues point at the layer that wrote the offending value (E03-23)."""

import pytest

from codekavach.config.errors import ConfigValidationError
from codekavach.config.overrides import parse_set_options
from tests.support.config import ConfigSandbox

CLOUD = (
    '[llm]\ndefault_provider = "primary"\n\n'
    '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
)


def first_issue(
    config_sandbox: ConfigSandbox, **kwargs: object
) -> tuple[str, str | None, int | None]:
    with pytest.raises(ConfigValidationError) as info:
        config_sandbox.load(**kwargs)
    issue = info.value.issues[0]
    return issue.code.value, issue.source, issue.line


def test_user_file(config_sandbox: ConfigSandbox) -> None:
    path = config_sandbox.write_user('[privacy]\nlevel = "L0"\n\n' + CLOUD)
    assert first_issue(config_sandbox) == ("CK-CFG-032", str(path), 2)


def test_project_file(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(CLOUD)
    path = config_sandbox.write_project('[project]\nname = "x"\n\n[privacy]\nlevel = "L0"\n')
    assert first_issue(config_sandbox) == ("CK-CFG-032", str(path), 5)


def test_profile(config_sandbox: ConfigSandbox) -> None:
    path = config_sandbox.write_user(CLOUD + '\n[profiles.airgap.privacy]\nlevel = "L0"\n')
    code, source, _ = first_issue(config_sandbox, profile="airgap")
    assert code == "CK-CFG-032"
    assert source == f"{path}#profiles.airgap"


def test_environment_variable(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(CLOUD)
    config_sandbox.env["CODEKAVACH_PRIVACY__LEVEL"] = "L0"
    assert first_issue(config_sandbox) == ("CK-CFG-032", "CODEKAVACH_PRIVACY__LEVEL", None)


def test_cli_override(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(CLOUD)
    overrides = parse_set_options(['privacy.level="L0"'])
    code, source, _ = first_issue(config_sandbox, cli_overrides=overrides)
    assert (code, source) == ("CK-CFG-032", "--set privacy.level")
