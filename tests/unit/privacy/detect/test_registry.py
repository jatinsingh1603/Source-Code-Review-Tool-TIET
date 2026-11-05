"""``DetectorRegistry`` and the ``codekavach.detectors`` entry-point group (E08-01)."""

import pytest

from codekavach.core.models import PlaceholderKind
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.privacy.detect.registry import DetectorRegistry
from tests.support.fake_detectors import ValueDetector

SECRET, PII, TERM = PlaceholderKind.SECRET, PlaceholderKind.PII, PlaceholderKind.TERM
GROUP = "codekavach.detectors"
FACTORIES = "tests.support.fake_detectors"


def plugin_registry(*names: str) -> PluginRegistry:
    return PluginRegistry(
        [PluginSpec(GROUP, name, f"{FACTORIES}:make_{name}", "ck-plugin", "1.0") for name in names]
    )


def test_register_all_and_for_kind_are_sorted_by_id() -> None:
    registry = DetectorRegistry()
    registry.register(ValueDetector("b.second", PII, "email", ["x"]))
    registry.register(ValueDetector("a.first", SECRET, "jwt", ["y"]))
    registry.register(ValueDetector("c.third", PII, "ipv4", ["z"]))
    assert [d.id for d in registry.all()] == ["a.first", "b.second", "c.third"]
    assert [d.id for d in registry.for_kind(PII)] == ["b.second", "c.third"]
    assert [d.id for d in registry.for_kind(TERM)] == []


def test_the_constructor_registers_the_given_detectors() -> None:
    registry = DetectorRegistry([ValueDetector("a.one", PII, "email", ["x"])])
    assert [d.id for d in registry.all()] == ["a.one"]


def test_a_duplicate_id_is_refused() -> None:
    registry = DetectorRegistry([ValueDetector("a.one", PII, "email", ["x"])])
    with pytest.raises(ValueError, match="already registered"):
        registry.register(ValueDetector("a.one", PII, "ipv4", ["y"]))


@pytest.mark.parametrize("bad_id", ["", "Upper", "has space", "1leading", "x" * 70])
def test_an_invalid_id_is_refused(bad_id: str) -> None:
    with pytest.raises(ValueError, match="id"):
        DetectorRegistry().register(ValueDetector(bad_id, PII, "email", ["x"]))


def test_a_detector_without_kinds_or_with_wrong_ones_is_refused() -> None:
    empty = ValueDetector("a.empty", PII, "email", ["x"])
    empty.kinds = frozenset()
    with pytest.raises(ValueError, match="kinds"):
        DetectorRegistry().register(empty)
    wrong = ValueDetector("a.wrong", PII, "email", ["x"])
    wrong.kinds = frozenset({"PII"})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="PlaceholderKind"):
        DetectorRegistry().register(wrong)


def test_an_object_that_is_not_a_detector_is_refused() -> None:
    with pytest.raises(TypeError):
        DetectorRegistry().register(object())  # type: ignore[arg-type]


def test_a_valid_plugin_detector_is_added_next_to_the_builtins() -> None:
    builtin = ValueDetector("secret.builtin", SECRET, "jwt", ["x"])
    registry = DetectorRegistry.from_plugins(plugin_registry("valid"), [builtin])
    assert [d.id for d in registry.all()] == ["plugin.valid", "secret.builtin"]


@pytest.mark.parametrize("name", ["without_detect", "bad_id", "empty_kinds"])
def test_a_plugin_that_is_not_a_proper_detector_is_skipped_not_registered(name: str) -> None:
    registry = DetectorRegistry.from_plugins(plugin_registry(name, "valid"))
    assert [d.id for d in registry.all()] == ["plugin.valid"]


def test_a_plugin_that_collides_with_a_builtin_id_is_skipped() -> None:
    builtin = ValueDetector("plugin.valid", SECRET, "jwt", ["x"])
    registry = DetectorRegistry.from_plugins(plugin_registry("valid"), [builtin])
    assert registry.all() == (builtin,)
