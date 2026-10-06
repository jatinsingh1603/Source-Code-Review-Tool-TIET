"""The helper behind the precedence matrix writes the right files for a mask (E03-43)."""

import tomllib

import pytest

from codekavach.config.constants import POLICY_FILE_NAME, PROJECT_FILE_NAME, USER_FILE_NAME
from codekavach.config.orgpolicy.model import OrgPolicy
from tests.support.config import ORG_POLICY_ENV, ConfigSandbox
from tests.support.config_matrix import (
    FIXTURES,
    LIST,
    MASKS,
    PROFILE,
    SCALAR,
    SOURCES,
    UNION,
    Kind,
    build_layers,
    expected_winner,
    fixture_text,
    label,
    present,
)

KINDS = (SCALAR, LIST, UNION)


def test_mask_zero_writes_nothing(config_sandbox: ConfigSandbox) -> None:
    assert build_layers(0, config_sandbox) == {}
    assert not (config_sandbox.home / USER_FILE_NAME).exists()
    assert not (config_sandbox.root / PROJECT_FILE_NAME).exists()
    assert ORG_POLICY_ENV not in config_sandbox.env
    assert set(config_sandbox.env) == {"CODEKAVACH_HOME"}


def test_mask_sixty_three_writes_every_source(config_sandbox: ConfigSandbox) -> None:
    keywords = build_layers(63, config_sandbox, SCALAR)
    assert keywords == {"profile": PROFILE, "cli_overrides": SCALAR.cli}
    user = (config_sandbox.home / USER_FILE_NAME).read_text(encoding="utf-8")
    assert user.startswith(fixture_text(SCALAR, "user"))
    assert "[profiles.matrix.scan]" in user
    assert (config_sandbox.root / PROJECT_FILE_NAME).read_text(encoding="utf-8") == fixture_text(
        SCALAR, "project"
    )
    assert config_sandbox.env[SCALAR.env_name] == SCALAR.env_value
    policy = config_sandbox.outside / POLICY_FILE_NAME
    assert config_sandbox.env[ORG_POLICY_ENV] == str(policy)
    assert policy.read_text(encoding="utf-8") == fixture_text(SCALAR, "policy")


def test_a_mixed_mask_writes_only_what_it_names(config_sandbox: ConfigSandbox) -> None:
    mask = 0b010100  # profile and cli
    assert present(mask) == ("profile", "cli")
    keywords = build_layers(mask, config_sandbox, LIST)
    assert keywords == {"profile": PROFILE, "cli_overrides": LIST.cli}
    # The profile is defined in the user file, so the file exists and holds only the profile.
    user = (config_sandbox.home / USER_FILE_NAME).read_text(encoding="utf-8")
    assert user == fixture_text(LIST, "profile")
    assert not (config_sandbox.root / PROJECT_FILE_NAME).exists()
    assert LIST.env_name not in config_sandbox.env
    assert ORG_POLICY_ENV not in config_sandbox.env


def test_the_enforcement_selects_the_policy_file(config_sandbox: ConfigSandbox) -> None:
    build_layers(0b100000, config_sandbox, SCALAR, enforcement="clamp")
    text = (config_sandbox.outside / POLICY_FILE_NAME).read_text(encoding="utf-8")
    assert 'enforcement = "clamp"' in text


def test_labels_are_unique_and_readable() -> None:
    labels = [label(mask) for mask in MASKS]
    assert len(set(labels)) == len(labels) == 64
    assert label(0) == "none"
    assert label(63) == "U-P-pr-E-C-L"
    assert label(0b010101) == "U-pr-C"


def test_present_follows_precedence_order() -> None:
    assert present(63) == SOURCES
    assert present(0b100001) == ("user", "lock")


@pytest.mark.parametrize(
    ("mask", "winner"),
    [(0, "default"), (0b100000, "default"), (0b000011, "project"), (0b110101, "cli")],
)
def test_expected_winner_ignores_the_lock(mask: int, winner: str) -> None:
    assert expected_winner(mask) == winner


@pytest.mark.parametrize("kind", KINDS, ids=lambda kind: kind.name)
@pytest.mark.parametrize("name", ["user", "project", "profile", "policy", "policy_clamp"])
def test_fixtures_are_valid_toml_and_the_policies_validate(kind: Kind, name: str) -> None:
    document = tomllib.loads(fixture_text(kind, name))
    if name.startswith("policy"):
        OrgPolicy.model_validate(document)


def test_every_fixture_directory_belongs_to_a_kind() -> None:
    directories = {path.name for path in FIXTURES.iterdir() if path.is_dir()}
    assert directories == {kind.name for kind in KINDS}


def test_each_source_has_a_distinct_value_per_kind() -> None:
    for kind in KINDS:
        values = [str(kind.values[name]) for name in SOURCES]
        assert len(set(values)) == len(SOURCES), kind.name
