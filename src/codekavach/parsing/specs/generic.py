"""The ``LanguageSpec`` implementation shared by the table-driven languages (E07-05b).

Owning epic: E07.

``TableSpec`` carries what the protocol asks of a language (keywords, builtins, node kinds) and
delegates scoping to ``generic_scopes`` and string context to ``c_style_literals``. The Kotlin, PHP,
C#, Ruby, C and C++ modules each build one and register it at import time.
"""

from collections.abc import Mapping
from typing import cast

from tree_sitter import Node as TSNode

from codekavach.core.models import Language
from codekavach.parsing.literals import LiteralContext
from codekavach.parsing.scopes import ScopeBuilder
from codekavach.parsing.spec import NodeKindMap
from codekavach.parsing.specs.c_style_literals import Shapes, literal_context
from codekavach.parsing.specs.generic_scopes import Names, Rules, bind, text_of


class TableSpec:
    """A ``LanguageSpec`` assembled from tables."""

    grammar_version = "tree-sitter-language-pack"
    class_body_sees_members = True

    def __init__(
        self,
        language: Language,
        *,
        keywords: frozenset[str],
        builtins: frozenset[str],
        kinds: NodeKindMap,
        rules: Rules,
        shapes: Shapes,
        comment_types: frozenset[str],
        members_visible: bool = True,
        extra_functions: Mapping[str, Names] | None = None,
    ) -> None:
        self.language = language
        # A bare member name resolves inside a method (Kotlin, C#, C++); PHP and Ruby need
        # ``$this->`` and ``@`` / ``self.``.
        self.class_scopes_visible = members_visible
        self.keywords = keywords
        self.builtins = builtins
        self._kinds = kinds
        self._rules = rules
        self._shapes = shapes
        self._comment_types = comment_types
        self._extra_functions = dict(extra_functions or {})

    def bind_scopes(self, root: object, builder: ScopeBuilder) -> None:
        """Feed ``builder`` the scopes and identifier occurrences of the tree rooted at ``root``."""
        bind(cast(TSNode, root), builder, self._rules)

    def definition_finders(self) -> tuple[Mapping[str, Names], Mapping[str, Names]]:
        """The name finders of the type-like and the function-like node types."""
        return self._rules.types, {**self._rules.functions, **self._extra_functions}

    def node_kinds(self) -> NodeKindMap:
        """Map each ``NodeKind`` to the grammar's node-type names that mean it."""
        return self._kinds

    def enclosing_symbol(self, node: object, source: str) -> str | None:
        """``Class.method``: the types and functions ``node`` is nested in, joined by dots."""
        start = cast(TSNode, node)
        if start.type in self._comment_types:
            return None
        names: list[str] = []
        current = start.parent
        while current is not None:
            finder = (
                self._rules.types.get(current.type)
                or self._rules.functions.get(current.type)
                or self._extra_functions.get(current.type)
            )
            if finder is not None:
                found = finder(current)
                if found:
                    names.append(text_of(found[0]))
            current = current.parent
        return ".".join(reversed(names)) if names else None

    def literal_context(self, node: object) -> LiteralContext:
        """The classifier context for the string-content node ``node``."""
        return literal_context(cast(TSNode, node), self._shapes)
