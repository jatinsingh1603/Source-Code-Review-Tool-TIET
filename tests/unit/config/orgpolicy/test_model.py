import tomllib
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from pydantic import ValidationError

from codekavach.config.orgpolicy.model import OrgPolicy
from codekavach.core.models import PrivacyLevel, TrustTier
from tests.support.config_strategies import org_policies

EXAMPLE = Path(__file__).resolve().parents[4] / "docs" / "examples" / "policy.minimal.toml"
MINIMAL = {"policy_version": 1, "organisation": "Example Bank Ltd"}


def test_minimal() -> None:
    policy = OrgPolicy.model_validate(MINIMAL)
    assert policy.enforcement == "reject"
    assert policy.privacy.min_level is None
    assert policy.lock == {}


def test_example_file_validates() -> None:
    policy = OrgPolicy.model_validate(tomllib.loads(EXAMPLE.read_text(encoding="utf-8")))
    assert policy.privacy.min_level is PrivacyLevel.L3
    assert policy.privacy.min_level_by_tier == {TrustTier.PUBLIC: PrivacyLevel.L4}
    assert policy.project_config.allow_trust is False
    assert policy.lock["privacy.vault.key_source"] == "keyring"


@pytest.mark.parametrize(
    "extra",
    [
        {"unknown": 1},
        {"privacy": {"min_levle": "L3"}},
        {"privacy": {"min_level": "L9"}},
        {"llm": {"allowed_kinds": ["telepathy"]}},
        {"llm": {"allow_remote": "sometimes"}},
        {"policy_version": 2},
        {"enforcement": "suggest"},
        {"organisation": ""},
    ],
)
def test_invalid(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        OrgPolicy.model_validate({**MINIMAL, **extra})


def test_lower_case_level_accepted() -> None:
    policy = OrgPolicy.model_validate({**MINIMAL, "privacy": {"min_level": "l4"}})
    assert policy.privacy.min_level is PrivacyLevel.L4


def test_lock_unknown_key_has_hint() -> None:
    with pytest.raises(ValidationError) as info:
        OrgPolicy.model_validate({**MINIMAL, "lock": {"privacy.levle": "L3"}})
    message = info.value.errors(include_input=False)[0]["msg"]
    assert "[CK-CFG-050]" in message
    assert "did you mean 'privacy.level'?" in message


def test_lock_mapping_entry_key_accepted() -> None:
    OrgPolicy.model_validate({**MINIMAL, "lock": {"llm.providers.lab.kind": "ollama"}})


@given(org_policies())
def test_strategy_generates_valid_policies(data: dict[str, Any]) -> None:
    OrgPolicy.model_validate(data)
