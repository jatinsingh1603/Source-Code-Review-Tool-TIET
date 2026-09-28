"""No layer of the chain user < project < profile < env < cli can go below the policy floor."""

from typing import Any

import pytest

from codekavach.config.errors import OrgPolicyError
from codekavach.core.models import PrivacyLevel
from tests.support.config import ConfigSandbox, to_toml

POLICY = {"policy_version": 1, "organisation": "Example Bank Ltd", "privacy": {"min_level": "L3"}}
LOOSE = '[privacy]\nlevel = "L2"\n'


@pytest.fixture
def sandbox(config_sandbox: ConfigSandbox) -> ConfigSandbox:
    config_sandbox.write_policy(to_toml(POLICY))
    config_sandbox.write_user('[privacy]\nlevel = "L4"\n')
    config_sandbox.write_project('[privacy]\nlevel = "L4"\n')
    return config_sandbox


def test_compliant_chain_loads(sandbox: ConfigSandbox) -> None:
    assert sandbox.load().settings.privacy.level is PrivacyLevel.L4


@pytest.mark.parametrize("layer", ["user", "project", "profile", "env", "cli"])
def test_each_layer_is_refused(sandbox: ConfigSandbox, layer: str) -> None:
    kwargs: dict[str, Any] = {"trust_project_config": True}
    if layer == "user":
        sandbox.write_user(LOOSE)
        sandbox.write_project("")
    elif layer == "project":
        sandbox.write_user("")
        sandbox.write_project(LOOSE)
    elif layer == "profile":
        sandbox.write_user('[privacy]\nlevel = "L4"\n\n[profiles.quick.privacy]\nlevel = "L2"\n')
        kwargs["profile"] = "quick"
    elif layer == "env":
        sandbox.env["CODEKAVACH_PRIVACY__LEVEL"] = "L2"
    else:
        kwargs["cli_overrides"] = {"privacy": {"level": "L2"}}
    with pytest.raises(OrgPolicyError) as info:
        sandbox.load(**kwargs)
    assert [issue.code.value for issue in info.value.issues] == ["CK-CFG-055"]
