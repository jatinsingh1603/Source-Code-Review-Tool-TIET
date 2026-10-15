"""Pinned grammar loading (E07-01)."""

import importlib.metadata

import pytest

from codekavach.core.models import Language
from codekavach.parsing.loader import (
    GRAMMAR_PINS,
    PINNED_PACK_VERSION,
    grammar_available,
    grammar_version,
    load_language,
    pack_version,
)


def test_grammar_available_for_python_and_javascript() -> None:
    assert grammar_available(Language.PYTHON) is True
    assert grammar_available(Language.JAVASCRIPT) is True


def test_grammar_available_is_false_for_an_unpinned_language_and_never_raises() -> None:
    assert Language.YAML not in GRAMMAR_PINS
    assert grammar_available(Language.YAML) is False


def test_load_language_returns_the_same_object_on_a_repeated_call() -> None:
    first = load_language(Language.PYTHON)
    second = load_language(Language.PYTHON)
    assert first is second


def test_load_language_raises_lookup_error_for_an_unpinned_language() -> None:
    with pytest.raises(LookupError):
        load_language(Language.YAML)


def test_grammar_version_raises_lookup_error_for_an_unpinned_language() -> None:
    with pytest.raises(LookupError):
        grammar_version(Language.YAML)


def test_grammar_version_matches_the_pin_for_every_supported_language() -> None:
    for language in GRAMMAR_PINS:
        assert grammar_version(language) == GRAMMAR_PINS[language]


def test_pack_version_drift() -> None:
    """The installed tree-sitter-language-pack version must match the recorded pin.

    A failure here means the pack was bumped without re-running the parsing conformance corpus
    and updating the golden files under tests/unit/parsing; do that, confirm no query or renamer
    regresses, and only then update PINNED_PACK_VERSION in codekavach/parsing/loader.py.
    """
    installed = pack_version()
    assert installed == PINNED_PACK_VERSION, (
        f"tree-sitter-language-pack {installed} does not match the pinned "
        f"{PINNED_PACK_VERSION}; re-run the parsing conformance corpus, update the golden "
        "files, then update PINNED_PACK_VERSION"
    )
    assert installed == importlib.metadata.version("tree-sitter-language-pack")
