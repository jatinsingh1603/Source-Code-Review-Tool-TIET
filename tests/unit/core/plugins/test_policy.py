"""The ``[plugins]`` allow-list and disable-list applied to discovered specs (E04-11).

``apply_policy`` works on ``PluginSpec`` records, which are read from distribution metadata; no
test here needs a module to exist, which is the point: nothing is imported to decide.
"""

import sys

import pytest

from codekavach.config.models.plugins import PluginsSettings
from codekavach.core.plugins.discovery import GROUPS, PluginSpec, kind_of
from codekavach.core.plugins.policy import apply_policy, disabled_reason
from codekavach.core.plugins.registry import PluginRegistry

STAGES = "codekavach.stages"


def spec(name: str, dist: str, group: str = STAGES) -> PluginSpec:
    # The target names a module that does not exist, so any import attempt would be a failure.
    return PluginSpec(group, name, f"{dist.replace('-', '_')}_missing:{name.title()}", dist, "1.0")


def settings(allow: list[str] | None = None, disable: list[str] | None = None) -> PluginsSettings:
    return PluginsSettings(allow_distributions=allow or [], disable=disable or [])


def names(specs: list[PluginSpec]) -> list[str]:
    return [f"{item.dist_name}:{item.name}" for item in specs]


SPECS = [
    spec("parse", "codekavach"),
    spec("sample", "acme-rules"),
    spec("sample", "evil-plugin"),
    spec("pdf", "acme-rules", "codekavach.renderers"),
]


# --- the truth table ---------------------------------------------------------------------------


def test_empty_settings_allow_everything() -> None:
    allowed, disabled = apply_policy(SPECS, settings())
    assert allowed == SPECS
    assert disabled == []


@pytest.mark.parametrize(
    ("allow", "expected_allowed"),
    [
        (["acme-rules"], ["codekavach:parse", "acme-rules:sample", "acme-rules:pdf"]),
        (["evil-plugin"], ["codekavach:parse", "evil-plugin:sample"]),
        (
            ["acme-rules", "evil-plugin"],
            ["codekavach:parse", "acme-rules:sample", "evil-plugin:sample", "acme-rules:pdf"],
        ),
        (["unrelated"], ["codekavach:parse"]),
        (["codekavach"], ["codekavach:parse"]),
    ],
    ids=["one", "other", "two", "miss", "core-only"],
)
def test_the_allow_list(allow: list[str], expected_allowed: list[str]) -> None:
    allowed, disabled = apply_policy(SPECS, settings(allow=allow))
    assert names(allowed) == expected_allowed
    assert sorted(names(allowed) + names(disabled)) == sorted(names(SPECS))


def test_the_core_distribution_is_always_allowed() -> None:
    allowed, disabled = apply_policy([spec("parse", "codekavach")], settings(allow=["acme-rules"]))
    assert names(allowed) == ["codekavach:parse"]
    assert disabled == []


def test_an_empty_allow_list_is_not_a_miss_for_the_core_distribution() -> None:
    assert apply_policy([spec("parse", "codekavach")], settings())[1] == []


@pytest.mark.parametrize(
    ("entry", "disabled_names"),
    [
        ("stage:sample", ["acme-rules:sample", "evil-plugin:sample"]),
        ("renderer:pdf", ["acme-rules:pdf"]),
        ("stage:parse", ["codekavach:parse"]),
        ("stage:missing", []),
        ("renderer:sample", []),  # the kind is part of the entry
    ],
)
def test_the_disable_list_names_a_plugin_in_every_distribution(
    entry: str, disabled_names: list[str]
) -> None:
    allowed, disabled = apply_policy(SPECS, settings(disable=[entry]))
    assert names(disabled) == disabled_names
    assert len(allowed) + len(disabled) == len(SPECS)


def test_disabled_and_not_allowed_combine() -> None:
    allowed, disabled = apply_policy(
        SPECS, settings(allow=["acme-rules"], disable=["renderer:pdf"])
    )
    assert names(allowed) == ["codekavach:parse", "acme-rules:sample"]
    assert names(disabled) == ["evil-plugin:sample", "acme-rules:pdf"]


def test_the_order_of_the_input_is_kept_in_both_lists() -> None:
    allowed, disabled = apply_policy(list(reversed(SPECS)), settings(allow=["acme-rules"]))
    assert names(allowed) == ["acme-rules:pdf", "acme-rules:sample", "codekavach:parse"]
    assert names(disabled) == ["evil-plugin:sample"]


def test_the_input_is_not_changed() -> None:
    before = list(SPECS)
    apply_policy(SPECS, settings(allow=["acme-rules"], disable=["stage:parse"]))
    assert before == SPECS


# --- distribution names are compared after PEP 503 normalisation ---


@pytest.mark.parametrize(
    ("configured", "installed"),
    [
        ("Foo_Bar.plugin", "foo-bar-plugin"),
        ("foo-bar-plugin", "Foo_Bar.plugin"),
        ("FOO--BAR__plugin", "foo.bar.plugin"),
        ("acme", "ACME"),
    ],
)
def test_names_are_normalised_on_both_sides(configured: str, installed: str) -> None:
    allowed, disabled = apply_policy([spec("x", installed)], settings(allow=[configured]))
    assert len(allowed) == 1
    assert disabled == []


@pytest.mark.parametrize(
    ("configured", "installed"),
    [("foo-bar", "foo-bar-plugin"), ("foo-bar-plugin", "foo-bar"), ("foobar", "foo-bar")],
)
def test_normalisation_does_not_match_different_names(configured: str, installed: str) -> None:
    allowed, disabled = apply_policy([spec("x", installed)], settings(allow=[configured]))
    assert allowed == []
    assert len(disabled) == 1


def test_a_spec_without_a_distribution_is_judged_as_unknown() -> None:
    orphan = spec("odd", "unknown")
    assert apply_policy([orphan], settings())[1] == []
    assert apply_policy([orphan], settings(allow=["acme-rules"]))[0] == []
    assert apply_policy([orphan], settings(allow=["unknown"]))[1] == []


# --- every kind of plugin can be disabled -------------------------------------------------------


@pytest.mark.parametrize("group", GROUPS)
def test_a_spec_of_each_kind_can_be_disabled(group: str) -> None:
    item = spec("thing", "acme-rules", group)
    entry = f"{kind_of(group)}:thing"
    allowed, disabled = apply_policy([item], settings(disable=[entry]))
    assert (allowed, disabled) == ([], [item])
    assert apply_policy([item], settings()) == ([item], [])


def test_the_six_kinds_are_the_entry_prefixes() -> None:
    assert sorted(kind_of(group) for group in GROUPS) == [
        "detector",
        "engine",
        "language",
        "provider",
        "renderer",
        "stage",
    ]


def test_disabled_reason_names_the_cause() -> None:
    item = spec("sample", "evil-plugin")
    assert disabled_reason(item, frozenset(), frozenset({"stage:sample"})) == "disabled"
    assert disabled_reason(item, frozenset({"acme-rules"}), frozenset()) == "not_allowed"
    both = disabled_reason(item, frozenset({"acme-rules"}), frozenset({"stage:sample"}))
    assert both == "disabled"
    assert disabled_reason(item, frozenset({"evil-plugin"}), frozenset()) is None


def test_nothing_is_imported_to_decide() -> None:
    apply_policy(SPECS, settings(allow=["acme-rules"], disable=["stage:parse"]))
    assert "evil_plugin_missing" not in sys.modules
    assert "acme_rules_missing" not in sys.modules


# --- the registry lists disabled plugins and never loads them ---


def test_the_registry_lists_disabled_specs_and_does_not_load_them() -> None:
    allowed, disabled = apply_policy(SPECS, settings(allow=["acme-rules"]))
    registry = PluginRegistry(allowed, disabled=disabled, validators={})
    rows = registry.rows()
    statuses = {(row.dist, row.name, row.group): row.status for row in rows}
    assert statuses[("evil-plugin", "sample", STAGES)] == "disabled"
    assert registry.disabled() == tuple(disabled)
    # The allowed specs point at modules that do not exist, so they fail to import: the disabled
    # one is not among the failures because it was never attempted.
    assert sorted(failure.spec.dist_name for failure in registry.failures()) == [
        "acme-rules",
        "acme-rules",
        "codekavach",
    ]
    disabled_rows = [row for row in rows if row.status == "disabled"]
    assert [row.dist for row in disabled_rows] == ["evil-plugin"]
    assert all(row.category is None and row.error_type is None for row in disabled_rows)


def test_a_disabled_spec_takes_no_part_in_a_name_collision() -> None:
    allowed, disabled = apply_policy(
        [spec("sample", "acme-rules"), spec("sample", "aaa-first")], settings(allow=["acme-rules"])
    )
    registry = PluginRegistry(allowed, disabled=disabled, validators={})
    assert registry.shadowed() == ()
    assert [spec_.dist_name for spec_ in registry.disabled()] == ["aaa-first"]


def test_disabled_specs_are_deduplicated_and_sorted() -> None:
    items = [spec("b", "x-dist"), spec("a", "x-dist"), spec("b", "x-dist")]
    registry = PluginRegistry([], disabled=items, validators={})
    assert [item.name for item in registry.disabled()] == ["a", "b"]
