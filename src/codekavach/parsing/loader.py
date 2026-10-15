"""Pinned tree-sitter grammar loading (E07-01).

Owning epic: E07.

``tree-sitter-language-pack`` (RESOURCE.md) ships every grammar as one versioned wheel. A
grammar update changes node types and can silently break a query or a renamer
(``docs/research/INSIGHTS.md`` section 5.1), so the exact pack version CodeKavach is built and
tested against is pinned here; a drift test fails loudly before a bump reaches a scan.

Loading is cached at process level: a ``tree_sitter.Language`` wraps a compiled grammar, and
rebuilding it per file would be wasted work across a scan of thousands of files.
"""

import importlib.metadata
from collections.abc import Mapping
from threading import Lock
from typing import cast

import tree_sitter_language_pack
from tree_sitter import Language as TSLanguage
from tree_sitter_language_pack import SupportedLanguage

from codekavach.core.log import get_logger
from codekavach.core.models import Language

_log = get_logger("codekavach.parsing")

PACK_DISTRIBUTION = "tree-sitter-language-pack"

# The tree-sitter-language-pack version CodeKavach is built and tested against. Every supported
# language is pinned to the same value because the pack ships and versions every grammar
# together. Bumping it means re-running the parsing conformance corpus and updating the golden
# files under tests/unit/parsing before this constant changes.
PINNED_PACK_VERSION = "0.9.0"

# Supported languages (docs/PLAN.md requirement R6). Each one's tree-sitter-language-pack key
# happens to equal its CodeKavach ``Language`` value; a future language whose pack key differs
# needs its own value-mapping entry, not a change to this assumption.
GRAMMAR_PINS: Mapping[Language, str] = {
    Language.PYTHON: PINNED_PACK_VERSION,
    Language.JAVASCRIPT: PINNED_PACK_VERSION,
    Language.TYPESCRIPT: PINNED_PACK_VERSION,
    Language.JAVA: PINNED_PACK_VERSION,
    Language.KOTLIN: PINNED_PACK_VERSION,
    Language.C: PINNED_PACK_VERSION,
    Language.CPP: PINNED_PACK_VERSION,
    Language.PHP: PINNED_PACK_VERSION,
    Language.GO: PINNED_PACK_VERSION,
    Language.CSHARP: PINNED_PACK_VERSION,
    Language.RUBY: PINNED_PACK_VERSION,
}

_lock = Lock()
_cache: dict[Language, TSLanguage] = {}


def pack_version() -> str:
    """The installed ``tree-sitter-language-pack`` distribution version."""
    return importlib.metadata.version(PACK_DISTRIBUTION)


def load_language(language: Language) -> TSLanguage:
    """Return the pinned grammar for ``language``, from a process-level cache.

    Raises:
        LookupError: ``language`` has no entry in ``GRAMMAR_PINS``, or the grammar library is
            not installed.
    """
    with _lock:
        cached = _cache.get(language)
        if cached is not None:
            return cached
        if language not in GRAMMAR_PINS:
            raise LookupError(f"no pinned tree-sitter grammar for {language.value!r}")
        key = cast(SupportedLanguage, language.value)
        loaded = tree_sitter_language_pack.get_language(key)
        _cache[language] = loaded
        return loaded


def grammar_available(language: Language) -> bool:
    """True when ``language`` has a pinned grammar that loads successfully; never raises."""
    try:
        load_language(language)
    except Exception as error:  # noqa: BLE001 - must never raise; the issue's own contract
        _log.debug("grammar_unavailable", language=language.value, error_type=type(error).__name__)
        return False
    return True


def grammar_version(language: Language) -> str:
    """The pinned grammar version string for ``language``.

    Raises:
        LookupError: ``language`` has no entry in ``GRAMMAR_PINS``.
    """
    try:
        return GRAMMAR_PINS[language]
    except KeyError:
        raise LookupError(f"no pinned tree-sitter grammar for {language.value!r}") from None
