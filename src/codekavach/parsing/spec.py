"""The ``LanguageSpec`` protocol and its registry (E07-01).

Owning epic: E07.

No language-specific knowledge lives here. This module ships the shape every language plugs
into: a small vocabulary of node kinds that is the same across languages (``NodeKind``), the
protocol a concrete spec implements (``LanguageSpec``) and a registry that holds whichever specs
have been registered. E07-02 and E07-05 add the real Python, JavaScript/TypeScript, Java, Go and
other specs by importing their module (which calls ``register`` at import time); this module
registers none of its own.

Third-party languages are expected to arrive the same way every other plugin kind does: an entry
point in the existing ``codekavach.languages`` group (``codekavach.core.plugins.discovery``),
loaded by the generic ``PluginRegistry``. That loading path is unchanged by this issue; a
``LanguageSpec`` loaded that way is registered into ``SpecRegistry`` by whoever loads it,
not by this module.
"""

from collections.abc import Mapping
from enum import StrEnum
from threading import Lock
from typing import Protocol, runtime_checkable

from codekavach.core.models import Language


class NodeKind(StrEnum):
    """A syntactic role, independent of any one grammar's node-type names."""

    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    CALL = "call"
    IMPORT = "import"
    ASSIGNMENT = "assignment"
    STRING = "string"
    COMMENT = "comment"
    IDENTIFIER = "identifier"
    PARAMETER = "parameter"
    FIELD = "field"
    DECORATOR = "decorator"
    BLOCK = "block"


NodeKindMap = Mapping[NodeKind, frozenset[str]]


@runtime_checkable
class LanguageSpec(Protocol):
    """What a language plugs into the parsing layer; implemented, never subclassed."""

    language: Language
    grammar_version: str
    keywords: frozenset[str]
    builtins: frozenset[str]

    def node_kinds(self) -> NodeKindMap:
        """Map each ``NodeKind`` to the grammar's node-type names that mean it."""
        ...

    def enclosing_symbol(self, node: object, source: str) -> str | None:
        """The qualified name of the function, method or class enclosing ``node``, if any."""
        ...


class UnknownLanguageError(LookupError):
    """``SpecRegistry.get`` was asked for a language with no registered spec."""

    def __init__(self, language: Language) -> None:
        self.language = language
        super().__init__(f"no LanguageSpec is registered for {language.value!r}")


class SpecRegistry:
    """Language specs registered at import time; a plain, process-wide lookup table."""

    def __init__(self) -> None:
        self._specs: dict[Language, LanguageSpec] = {}
        self._lock = Lock()

    def register(self, spec: LanguageSpec) -> None:
        """Register ``spec`` under ``spec.language``, replacing any earlier spec for it."""
        with self._lock:
            self._specs[spec.language] = spec

    def get(self, language: Language) -> LanguageSpec:
        """The registered spec for ``language``.

        Raises:
            UnknownLanguageError: no spec is registered for ``language``.
        """
        try:
            return self._specs[language]
        except KeyError:
            raise UnknownLanguageError(language) from None

    def languages(self) -> tuple[Language, ...]:
        """Languages with a registered spec, in registration order."""
        return tuple(self._specs.keys())


REGISTRY = SpecRegistry()
