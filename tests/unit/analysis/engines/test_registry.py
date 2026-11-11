"""Engine selection: precedence, licence and hosted gates, plugins and the inventory (E14-01)."""

from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest

import codekavach.core.plugins.registry as plugin_registry
from codekavach.analysis.engines import registry as registry_module
from codekavach.analysis.engines.base import EngineAdapter, EngineProbe
from codekavach.analysis.engines.errors import (
    LICENCE_ATTESTATION_SENTENCE,
    EngineLicenceBlocked,
)
from codekavach.analysis.engines.manifest import licence_inventory, parse_manifest
from codekavach.analysis.engines.registry import (
    EngineRegistry,
    default_registry,
    is_hosted_deployment,
)
from codekavach.config import Settings
from codekavach.core.models import Language
from tests.support.engines import FakeAdapter

PY = [Language.PYTHON]


def settings(**engines: Any) -> Settings:
    return Settings.model_validate({"engines": engines})


def ids(
    registry: EngineRegistry, config: Settings, languages: list[Language] = PY, **kw: Any
) -> list[str]:
    return [a.spec.id for a in registry.resolve(config, languages, **kw).adapters]


@pytest.fixture
def registry() -> EngineRegistry:
    found = EngineRegistry()
    for engine_id in ("alpha", "beta", "gamma"):
        found.register(FakeAdapter(engine_id))
    return found


def test_with_no_settings_every_applicable_engine_is_selected(registry: EngineRegistry) -> None:
    assert ids(registry, settings()) == ["alpha", "beta", "gamma"]


@pytest.mark.parametrize(
    ("engines", "expected"),
    [
        # the lists
        ({"enabled": ["beta"]}, ["beta"]),
        ({"disabled": ["beta"]}, ["alpha", "gamma"]),
        # options.<id>.enabled beats the lists, in both directions
        (
            {"disabled": ["beta"], "options": {"beta": {"enabled": True}}},
            ["alpha", "beta", "gamma"],
        ),
        ({"enabled": ["beta", "alpha"], "options": {"beta": {"enabled": False}}}, ["alpha"]),
        # an option can switch an engine on although the list names others
        ({"enabled": ["alpha"], "options": {"gamma": {"enabled": True}}}, ["alpha", "gamma"]),
        # and off when the list is empty
        ({"options": {"alpha": {"enabled": False}}}, ["beta", "gamma"]),
    ],
)
def test_precedence(registry: EngineRegistry, engines: dict[str, Any], expected: list[str]) -> None:
    assert ids(registry, settings(**engines)) == expected


def test_the_same_id_in_both_lists_is_refused_by_the_settings() -> None:
    with pytest.raises(ValueError, match="CK-CFG-035"):
        settings(enabled=["alpha"], disabled=["alpha"])


def test_an_engine_without_an_applicable_language_is_left_out(registry: EngineRegistry) -> None:
    registry.register(FakeAdapter("jvm", languages=frozenset({Language.JAVA})))
    assert "jvm" not in ids(registry, settings(enabled=["jvm", "alpha"]))
    assert "jvm" in ids(registry, settings(enabled=["jvm"]), [Language.JAVA])


def test_default_enabled_false_needs_to_be_listed(registry: EngineRegistry) -> None:
    registry.register(FakeAdapter("opt-in", default_enabled=False))
    assert "opt-in" not in ids(registry, settings())
    assert ids(registry, settings(enabled=["opt-in"])) == ["opt-in"]


def test_an_empty_list_keeps_only_installed_engines_but_a_listed_one_stays(
    registry: EngineRegistry,
) -> None:
    registry.register(FakeAdapter("missing", available=False))

    def probe(adapter: EngineAdapter) -> EngineProbe:
        return adapter.probe(settings())

    assert "missing" not in ids(registry, settings(), probe=probe)
    assert "missing" in ids(registry, settings(enabled=["missing"]), probe=probe)


def test_unknown_ids_are_reported_and_do_not_raise(registry: EngineRegistry) -> None:
    config = settings(enabled=["alpha", "nosuch"], disabled=["other"], options={"third": {}})
    resolution = registry.resolve(config, PY)
    assert resolution.unknown_ids == ("nosuch", "other", "third")
    assert [a.spec.id for a in resolution.adapters] == ["alpha"]


def test_a_duplicate_id_is_refused(registry: EngineRegistry) -> None:
    with pytest.raises(ValueError, match="already registered"):
        registry.register(FakeAdapter("alpha"))


def restricted(registry: EngineRegistry) -> None:
    registry.register(FakeAdapter("share", scans_proprietary_code=False))


def test_a_restricted_licence_is_left_out_by_default(registry: EngineRegistry) -> None:
    restricted(registry)
    resolution = registry.resolve(settings(), PY)
    assert "share" not in [a.spec.id for a in resolution.adapters]
    assert resolution.blocked == ()


def test_enabling_a_restricted_engine_without_attestation_raises_with_the_sentence(
    registry: EngineRegistry,
) -> None:
    restricted(registry)
    with pytest.raises(EngineLicenceBlocked) as raised:
        registry.resolve_enabled(settings(enabled=["share"]), PY)
    assert raised.value.reason == "licence_attestation"
    assert LICENCE_ATTESTATION_SENTENCE in str(raised.value)
    assert raised.value.engine_id == "share"


@pytest.mark.parametrize("value", [True, "yes", "I confirm"])
def test_the_attestation_lets_a_restricted_engine_run(
    registry: EngineRegistry, value: object
) -> None:
    restricted(registry)
    config = settings(
        enabled=["share"], options={"share": {"options": {"licence_attestation": value}}}
    )
    assert "share" in [a.spec.id for a in registry.resolve_enabled(config, PY)]


@pytest.mark.parametrize("value", [False, "false", "", "0"])
def test_a_false_attestation_does_not_count(registry: EngineRegistry, value: object) -> None:
    restricted(registry)
    config = settings(
        enabled=["share"], options={"share": {"options": {"licence_attestation": value}}}
    )
    with pytest.raises(EngineLicenceBlocked):
        registry.resolve_enabled(config, PY)


def test_a_hosted_deployment_refuses_an_engine_that_is_not_hosted_allowed(
    registry: EngineRegistry,
) -> None:
    registry.register(FakeAdapter("copyleft", hosted_allowed=False))
    hosted = registry.resolve(settings(), PY, hosted=True)
    assert "copyleft" not in [a.spec.id for a in hosted.adapters]
    [(engine_id, error)] = hosted.blocked
    assert engine_id == "copyleft"
    assert error.reason == "hosted"
    assert LICENCE_ATTESTATION_SENTENCE not in str(error)
    local = registry.resolve(settings(), PY, hosted=False)
    assert "copyleft" in [a.spec.id for a in local.adapters]
    assert local.blocked == ()


def test_the_manifest_can_make_an_engine_hosted_unfriendly(registry: EngineRegistry) -> None:
    manifest = parse_manifest(
        '[engines.alpha]\npinned_version = "1"\nmin_version = "1"\nspdx_licence = "MIT"\n'
        'distribution = "bundled"\nhosted_allowed = false\nscans_proprietary_code = true\n'
        'install = "x"\ntelemetry_env = { A = "1" }\n'
    )
    resolution = registry.resolve(settings(), PY, hosted=True, manifest=manifest)
    assert [e for e, _ in resolution.blocked] == ["alpha"]


@pytest.mark.parametrize(
    ("value", "hosted"),
    [("hosted", True), (" Hosted ", True), ("local", False), ("", False)],
)
def test_the_environment_marks_a_hosted_deployment(value: str, hosted: bool) -> None:
    assert is_hosted_deployment({registry_module.HOSTED_VARIABLE: value}) is hosted
    assert is_hosted_deployment({}) is False


def fake_plugins(plugins: dict[str, object]) -> Callable[[Settings], SimpleNamespace]:
    return lambda _settings: SimpleNamespace(engines=lambda: plugins)


def test_only_well_formed_plugins_are_registered(
    registry: EngineRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        plugin_registry,
        "registry_from_environment",
        fake_plugins(
            {
                "extra": FakeAdapter("extra"),
                "alpha": FakeAdapter("alpha"),  # taken by a built-in
                "mismatch": FakeAdapter("other"),  # name differs from the spec id
                "junk": object(),
            }
        ),
    )
    assert registry.load_plugins(settings()) == ["extra"]
    assert "other" not in registry and "junk" not in registry


@pytest.fixture
def default_with_fake() -> Iterator[None]:
    default_registry().register(FakeAdapter("inventory-one"))
    try:
        yield
    finally:
        default_registry().unregister("inventory-one")


def test_the_licence_inventory_lists_the_registered_engines(default_with_fake: None) -> None:
    rows = licence_inventory()
    assert "inventory-one" in [row.engine for row in rows]
    row = next(r for r in rows if r.engine == "inventory-one")
    assert row.spdx_licence == "MIT" and row.hosted_allowed is True
