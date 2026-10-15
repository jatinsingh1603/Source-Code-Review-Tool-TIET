"""Parsing.

The tree-sitter loader, LanguageSpec, queries, symbols, scopes, imports and the call graph.

Owning epic: E07. Normative layout: docs/ARCHITECTURE.md section 3.

Importing this package registers the built-in Python, JavaScript and TypeScript specs
(``codekavach.parsing.specs``), so ``parse()`` extracts identifiers, string literals and
comments for those three languages without the caller doing anything further.
"""

import codekavach.parsing.specs as _specs  # noqa: F401 - import side effect: registers the specs
from codekavach.parsing.literals import LiteralContext, LiteralKind, classify_literal
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
    "LiteralContext",
    "LiteralKind",
    "LiteralSpan",
    "NodeKind",
    "NodeKindMap",
    "ParseUnavailableError",
    "ParsedFile",
    "SourceTooLargeError",
    "SpecRegistry",
    "UnknownLanguageError",
    "classify_literal",
    "grammar_available",
    "grammar_version",
    "load_language",
    "normalise_source",
    "pack_version",
    "parse",
]
