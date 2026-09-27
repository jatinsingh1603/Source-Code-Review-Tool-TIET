import re
import tomllib
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.models.privacy import (
    DEFAULT_NEVER_SEND,
    PathRule,
    PrivacySettings,
    VaultSettings,
)
from codekavach.core.models import PrivacyLevel, TrustTier

EXAMPLE = """
[privacy]
level = "L3"
domain_terms = ["kavachbank", "interest-accrual"]

[[privacy.paths]]
pattern = "src/engine/fees/**"
level = "L4"

[[privacy.paths]]
pattern = "config/keys/**"
never_send = true
"""


def message(error: ValidationError) -> str:
    details = error.errors()[0]
    return str(details.get("ctx", {}).get("error", details["msg"]))


def test_defaults() -> None:
    privacy = Settings().privacy
    assert privacy.level is PrivacyLevel.L3
    assert privacy.min_level is PrivacyLevel.L1
    assert privacy.provider_tier_levels == {
        TrustTier.LOCAL: PrivacyLevel.L1,
        TrustTier.PRIVATE: PrivacyLevel.L2,
        TrustTier.PUBLIC: PrivacyLevel.L3,
    }
    assert privacy.paths == []
    assert privacy.never_send == DEFAULT_NEVER_SEND
    assert privacy.domain_terms == []
    assert privacy.domain_terms_file is None
    assert privacy.public_allowlist_extra == []
    assert privacy.vault.key_source == "keyring"
    assert privacy.vault.passphrase is None
    assert privacy.floor_for_tier(TrustTier.PUBLIC) is PrivacyLevel.L3


def test_partial_tier_map_is_completed() -> None:
    privacy = PrivacySettings.model_validate({"provider_tier_levels": {"public": "L4"}})
    assert privacy.provider_tier_levels[TrustTier.PUBLIC] is PrivacyLevel.L4
    assert privacy.provider_tier_levels[TrustTier.LOCAL] is PrivacyLevel.L1


def test_example_and_floor_violation() -> None:
    data = tomllib.loads(EXAMPLE)
    settings = Settings.model_validate(data)
    assert settings.privacy.paths[0].level is PrivacyLevel.L4
    data["privacy"]["min_level"] = "L3"
    data["privacy"]["paths"][0]["level"] = "L2"
    with pytest.raises(ValidationError) as info:
        Settings.model_validate(data)
    assert message(info.value).startswith("[CK-CFG-037]")


def test_level_below_min_level() -> None:
    with pytest.raises(ValidationError) as info:
        PrivacySettings.model_validate({"level": "L2", "min_level": "L3"})
    assert message(info.value).startswith("[CK-CFG-037]")


def test_weak_tier_level_is_not_an_error() -> None:
    privacy = PrivacySettings.model_validate(
        {"min_level": "L3", "provider_tier_levels": {"local": "L1"}}
    )
    assert privacy.floor_for_tier(TrustTier.LOCAL) is PrivacyLevel.L3


@pytest.mark.parametrize(
    "rule",
    [
        {"pattern": "a/**", "level": "L3", "never_send": True},
        {"pattern": "a/**"},
        {"pattern": "/abs/**", "level": "L3"},
        {"pattern": "../x", "level": "L3"},
        {"pattern": "a/../b", "level": "L3"},
        {"pattern": "C:/x", "level": "L3"},
        {"pattern": "a\\b", "level": "L3"},
        {"pattern": "", "level": "L3"},
        {"pattern": "x" * 257, "level": "L3"},
    ],
)
def test_invalid_path_rules(rule: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as info:
        PrivacySettings.model_validate({"paths": [rule]})
    assert message(info.value).startswith("[CK-CFG-039]")


def test_invalid_never_send_pattern() -> None:
    with pytest.raises(ValidationError) as info:
        PrivacySettings.model_validate({"never_send": ["/etc/**"]})
    assert message(info.value).startswith("[CK-CFG-039]")


def test_too_many_rules() -> None:
    rules = [{"pattern": f"p{i}/**", "level": "L3"} for i in range(501)]
    with pytest.raises(ValidationError):
        PrivacySettings.model_validate({"paths": rules})


def test_vault_passphrase_required() -> None:
    with pytest.raises(ValidationError) as info:
        PrivacySettings.model_validate({"vault": {"key_source": "passphrase"}})
    assert message(info.value).startswith("[CK-CFG-033]")
    ok = PrivacySettings.model_validate(
        {"vault": {"key_source": "passphrase", "passphrase": "env:CODEKAVACH_VAULT_PASSPHRASE"}}
    )
    assert ok.vault.passphrase == "env:CODEKAVACH_VAULT_PASSPHRASE"


@pytest.mark.parametrize("name", ["a", "1abc", "has-dash", "x" * 65])
def test_public_allowlist_extra_rejects(name: str) -> None:
    with pytest.raises(ValidationError):
        PrivacySettings.model_validate({"public_allowlist_extra": [name]})


def test_public_allowlist_extra_accepts() -> None:
    names = ["getAccount", "_private", "$el"]
    assert (
        PrivacySettings.model_validate({"public_allowlist_extra": names}).public_allowlist_extra
        == names
    )


def test_markers() -> None:
    defs = Settings.model_json_schema()["$defs"]
    privacy = defs["PrivacySettings"]["properties"]
    assert privacy["domain_terms"]["x-ck-sensitive"] is True
    assert privacy["domain_terms"]["x-ck-merge"] == "union"
    assert privacy["never_send"]["x-ck-merge"] == "union"
    assert privacy["public_allowlist_extra"]["x-ck-restricted"] is True
    vault = defs["VaultSettings"]["properties"]
    assert vault["key_source"]["x-ck-restricted"] is True
    assert vault["passphrase"]["x-ck-restricted"] is True


def test_consent_is_not_a_setting() -> None:
    with pytest.raises(ValidationError) as info:
        Settings.model_validate({"privacy": {"egress_acknowledged": True}})
    assert info.value.errors()[0]["type"] == "extra_forbidden"
    with pytest.raises(ValidationError) as info:
        Settings.model_validate({"egress": {"acknowledged": True}})
    assert info.value.errors()[0]["type"] == "extra_forbidden"


def test_no_off_switch_fields() -> None:
    forbidden = re.compile(r"disable|skip|bypass|unsafe|allow_raw|consent|acknowledg")
    for model in (PrivacySettings, PathRule, VaultSettings):
        for name in model.model_fields:
            assert not forbidden.search(name), f"{model.__name__}.{name}"


# properties

_level = st.sampled_from(list(PrivacyLevel))


@given(
    _level,
    _level,
    st.dictionaries(st.sampled_from(list(TrustTier)), _level),
    st.lists(_level, max_size=5),
)
def test_validation_iff_levels_meet_floor(
    level: PrivacyLevel,
    min_level: PrivacyLevel,
    tiers: dict[TrustTier, PrivacyLevel],
    path_levels: list[PrivacyLevel],
) -> None:
    data = {
        "level": level.value,
        "min_level": min_level.value,
        "provider_tier_levels": {tier.value: value.value for tier, value in tiers.items()},
        "paths": [
            {"pattern": f"p{i}/**", "level": value.value} for i, value in enumerate(path_levels)
        ],
    }
    expected_ok = level.at_least(min_level) and all(p.at_least(min_level) for p in path_levels)
    try:
        privacy = PrivacySettings.model_validate(data)
    except ValidationError:
        assert not expected_ok
        return
    assert expected_ok
    for tier in TrustTier:
        assert privacy.floor_for_tier(tier).at_least(min_level)
