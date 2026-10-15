"""The ``LanguageSpec`` protocol and ``SpecRegistry`` (E07-01)."""

import pytest

from codekavach.core.models import Language
from codekavach.parsing.spec import LanguageSpec, SpecRegistry, UnknownLanguageError
from tests.support.parsing import TrivialSpec


def test_trivial_spec_satisfies_the_protocol() -> None:
    assert isinstance(TrivialSpec(), LanguageSpec)


def test_registry_get_raises_for_an_unregistered_language() -> None:
    registry = SpecRegistry()
    with pytest.raises(UnknownLanguageError):
        registry.get(Language.PYTHON)


def test_registry_register_and_get_round_trip() -> None:
    registry = SpecRegistry()
    spec = TrivialSpec()
    registry.register(spec)
    assert registry.get(Language.PYTHON) is spec
    assert registry.languages() == (Language.PYTHON,)


def test_registry_register_replaces_an_earlier_spec_for_the_same_language() -> None:
    registry = SpecRegistry()
    first = TrivialSpec()
    second = TrivialSpec()
    registry.register(first)
    registry.register(second)
    assert registry.get(Language.PYTHON) is second
    assert registry.languages() == (Language.PYTHON,)
