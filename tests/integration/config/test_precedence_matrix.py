"""Every combination of the six configuration sources, exhaustively (E03-43).

Sources, lowest to highest: user file, project file, profile, environment, CLI flags; above them
the organisation policy lock. For a scalar and a list (arrays replace, ADR D3) all 64 subsets are
loaded and the winner and its ``Origin`` are asserted; for a union-merged key the contributions of
every subset must all be present. A change to the layer order, or a layer inserted in the wrong
place, fails here by name: the test id lists the sources present (``U-P-pr-E-C-L``).

Reject mode and the lock: a locked key must already hold the locked value, so every subset that
includes the lock fails with CK-CFG-055, including the one with the lock alone (the default is not
the locked value). Clamp mode applies the locked value and records the policy as its origin.
"""

import json
from typing import Any

import pytest

from codekavach.config import Origin, Settings
from codekavach.config.constants import USER_FILE_NAME
from codekavach.config.errors import ConfigErrorCode, OrgPolicyError
from tests.support.cli import run_cli
from tests.support.config import ConfigSandbox
from tests.support.config_matrix import (
    LIST,
    MASKS,
    PROFILE,
    SCALAR,
    UNION,
    Kind,
    build_layers,
    expected_winner,
    label,
    present,
)

WITH_LOCK = [mask for mask in MASKS if "lock" in present(mask)]
WITHOUT_LOCK = [mask for mask in MASKS if "lock" not in present(mask)]
KINDS = [SCALAR, LIST]
LOCK_ONLY = 0b100000


def value_of(settings: Settings, key: str) -> Any:
    """The JSON-mode value at a dotted key."""
    node: Any = settings.model_dump(mode="json")
    for part in key.split("."):
        node = node[part]
    return node


def assert_origin(origin: Origin, winner: str, sandbox: ConfigSandbox) -> None:
    assert origin.layer == winner
    user_file = str(sandbox.home / USER_FILE_NAME)
    project_file = str(sandbox.root / "codekavach.toml")
    if winner == "default":
        assert origin.source is None
    elif winner == "user":
        assert (origin.source, origin.line) == (user_file, 2)
    elif winner == "project":
        assert (origin.source, origin.line) == (project_file, 2)
    elif winner == "profile":
        assert origin.source is not None
        assert user_file in origin.source
        assert PROFILE in origin.source
    elif winner == "env":
        assert origin.source is not None
        assert origin.source.startswith("CODEKAVACH_")
    else:
        assert winner == "cli"
        assert origin.source == "cli"


@pytest.mark.parametrize("mask", WITHOUT_LOCK, ids=label)
@pytest.mark.parametrize("kind", KINDS, ids=lambda kind: kind.name)
def test_the_highest_source_wins(kind: Kind, mask: int, config_sandbox: ConfigSandbox) -> None:
    keywords = build_layers(mask, config_sandbox, kind)
    loaded = config_sandbox.load(**keywords)
    winner = expected_winner(mask)
    expected = kind.default if winner == "default" else kind.values[winner]
    assert value_of(loaded.settings, kind.key) == expected
    assert_origin(loaded.origins[kind.key], winner, config_sandbox)
    assert loaded.locked_keys == frozenset()


@pytest.mark.parametrize("mask", WITH_LOCK, ids=label)
@pytest.mark.parametrize("kind", KINDS, ids=lambda kind: kind.name)
def test_reject_mode_refuses_every_subset_that_differs_from_the_lock(
    kind: Kind, mask: int, config_sandbox: ConfigSandbox
) -> None:
    keywords = build_layers(mask, config_sandbox, kind)
    with pytest.raises(OrgPolicyError) as info:
        config_sandbox.load(**keywords)
    assert [issue.code for issue in info.value.issues] == [ConfigErrorCode.CK_CFG_055]
    assert info.value.issues[0].key == kind.key


@pytest.mark.parametrize("mask", WITH_LOCK, ids=label)
@pytest.mark.parametrize("kind", KINDS, ids=lambda kind: kind.name)
def test_clamp_mode_applies_the_lock_over_every_subset(
    kind: Kind, mask: int, config_sandbox: ConfigSandbox
) -> None:
    keywords = build_layers(mask, config_sandbox, kind, enforcement="clamp")
    loaded = config_sandbox.load(**keywords)
    assert value_of(loaded.settings, kind.key) == kind.values["lock"]
    origin = loaded.origins[kind.key]
    assert origin.layer == "org-policy"
    assert origin.source == str(config_sandbox.outside / "policy.toml")
    assert kind.key in loaded.locked_keys
    warnings = [issue for issue in loaded.warnings if issue.code is ConfigErrorCode.CK_CFG_055]
    assert [issue.key for issue in warnings] == [kind.key]


@pytest.mark.parametrize("kind", KINDS, ids=lambda kind: kind.name)
def test_a_source_that_agrees_with_the_lock_is_not_a_violation(
    kind: Kind, config_sandbox: ConfigSandbox
) -> None:
    # The user file holds the locked value itself, so reject mode has nothing to refuse and the
    # origin stays the user file: the policy changed nothing.
    keywords = build_layers(LOCK_ONLY, config_sandbox, kind)
    locked = kind.values["lock"]
    if kind is SCALAR:
        config_sandbox.write_user(f"[scan]\nmax_file_size_kb = {locked}\n")
    else:
        config_sandbox.write_user(f"[reporting]\nformats = {json.dumps(locked)}\n")
    loaded = config_sandbox.load(**keywords)
    assert value_of(loaded.settings, kind.key) == locked
    assert loaded.origins[kind.key].layer == "user"
    assert kind.key in loaded.locked_keys


# --- union-merged keys only ever grow ----------------------------------------------------------


@pytest.mark.parametrize("mask", MASKS, ids=label)
def test_union_key_keeps_every_contribution(mask: int, config_sandbox: ConfigSandbox) -> None:
    keywords = build_layers(mask, config_sandbox, UNION)
    loaded = config_sandbox.load(**keywords)
    value = value_of(loaded.settings, UNION.key)
    defaults = value_of(Settings(), UNION.key)
    contributions = [UNION.values[name][0] for name in present(mask)]
    assert value == [*defaults, *contributions]
    assert set(defaults) <= set(value)
    origin = loaded.origins[UNION.key]
    layers = [name for name in present(mask) if name != "lock"]
    if "lock" in present(mask):
        layers.append("org-policy")
    assert origin.contributors == (("default", *layers) if defaults else tuple(layers))


def test_a_union_key_cannot_be_lowered_by_a_higher_layer(config_sandbox: ConfigSandbox) -> None:
    keywords = build_layers(0b011111, config_sandbox, UNION)
    config_sandbox.write_project("[privacy]\nnever_send = []\n")
    loaded = config_sandbox.load(**keywords)
    assert {"u/**", "pr/**", "e/**", "c/**"} <= set(value_of(loaded.settings, UNION.key))


# --- CLI option variables ---------------------------------------------------------------------

PROVIDERS = (
    '[llm.providers.alpha]\nkind = "ollama"\nmodel = "m1"\n'
    '[llm.providers.beta]\nkind = "ollama"\nmodel = "m2"\n'
)
SETTINGS_VARIABLE = {"CODEKAVACH_LLM__DEFAULT_PROVIDER": "alpha"}


def default_provider(
    sandbox: ConfigSandbox, env: dict[str, str], *args: str
) -> tuple[Any, dict[str, Any]]:
    """The effective ``llm.default_provider`` and its origin, through ``config show``."""
    result = run_cli(
        ["config", "show", "--origin", "--format", "json", "--section", "llm", *args],
        cwd=sandbox.root,
        home=sandbox.home,
        env={**sandbox.env, **env},
    )
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    provider = document["settings"]["llm"]["default_provider"]
    return provider, document["origins"]["llm.default_provider"]


def test_the_option_variable_outranks_the_settings_variable(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(PROVIDERS)
    value, origin = default_provider(config_sandbox, SETTINGS_VARIABLE)
    assert (value, origin["layer"], origin["source"]) == (
        "alpha",
        "env",
        "CODEKAVACH_LLM__DEFAULT_PROVIDER",
    )
    both = {**SETTINGS_VARIABLE, "CODEKAVACH_PROVIDER": "beta"}
    value, origin = default_provider(config_sandbox, both)
    assert (value, origin["layer"], origin["source"]) == ("beta", "cli", "--provider")


def test_the_option_variable_records_what_the_flag_would(config_sandbox: ConfigSandbox) -> None:
    config_sandbox.write_user(PROVIDERS)
    both = {**SETTINGS_VARIABLE, "CODEKAVACH_PROVIDER": "beta"}
    from_variable = default_provider(config_sandbox, both)
    from_flag = default_provider(config_sandbox, SETTINGS_VARIABLE, "--provider", "beta")
    assert from_variable == from_flag
