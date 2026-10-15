"""Parsing.

The tree-sitter loader, LanguageSpec, queries, symbols, scopes, imports and the call graph.

Owning epic: E07. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.parsing.loader import (
    GRAMMAR_PINS,
    PINNED_PACK_VERSION,
    grammar_available,
    grammar_version,
    load_language,
    pack_version,
)
from codekavach.parsing.models import LiteralSpan, ParsedFile
from codekavach.parsing.normalise import HiddenCharReport, HiddenKind, normalise_source
from codekavach.parsing.parser import ParseUnavailableError, SourceTooLargeError, parse
from codekavach.parsing.positions import LineIndex
from codekavach.parsing.spec import (
    REGISTRY,
    LanguageSpec,
    NodeKind,
    NodeKindMap,
    SpecRegistry,
    UnknownLanguageError,
)

__all__ = [
    "GRAMMAR_PINS",
    "PINNED_PACK_VERSION",
    "REGISTRY",
    "HiddenCharReport",
    "HiddenKind",
    "LanguageSpec",
    "LineIndex",
    "LiteralSpan",
    "NodeKind",
    "NodeKindMap",
    "ParseUnavailableError",
    "ParsedFile",
    "SourceTooLargeError",
    "SpecRegistry",
    "UnknownLanguageError",
    "grammar_available",
    "grammar_version",
    "load_language",
    "normalise_source",
    "pack_version",
    "parse",
]
