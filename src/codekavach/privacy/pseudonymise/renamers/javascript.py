"""The JavaScript and TypeScript renamers (E09-04).

Owning epic: E09. Normative layout: docs/ARCHITECTURE.md section 3.

One token per name covers declarations (``var``, ``let``, ``const``, functions, classes, methods,
arrows), parameters and their defaults, computed keys, import and export specifiers with ``as``
aliases, template substitutions, tagged templates, JSX names, optional chaining, non-null
assertions and, in TypeScript, interface, type-alias and enum names, generics and parameter
properties. Two forms need more:

**Shorthand.** ``{ accountId }`` is one node that is both a key and a binding. When the binding is
internal it is expanded to ``{ accountId: var_1 }``, in an object literal and in a destructuring
pattern alike, so that a consumer reading the property by name still works. The key therefore
stays in the text; it is counted (``shorthand_expanded``) because the key is the wire contract
the issue asked to preserve, and the leakage harness has to see it. A public binding is left
alone.

**Private fields.** ``#secret`` keeps its ``#``: the token is ``#field_3``.

The TypeScript variant reuses the rules: the grammar names the same nodes.
"""

from functools import lru_cache

from tree_sitter import Query, QueryCursor

from codekavach.core.models import Language
from codekavach.parsing.loader import load_language
from codekavach.parsing.models import ParsedFile
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.plan import EditReason, RenameEdit
from codekavach.privacy.pseudonymise.renamers.base import BaseRenamer, SourceFacts

_SHORTHAND_QUERY = """
(shorthand_property_identifier) @shorthand
(shorthand_property_identifier_pattern) @shorthand
(import_statement source: (string) @specifier)
(export_statement source: (string) @specifier)
(call_expression
  function: (identifier) @callee
  arguments: (arguments . (string) @specifier)
  (#eq? @callee "require"))
"""


@lru_cache(maxsize=4)
def _shorthand_query(language: Language) -> Query:
    return Query(load_language(language), _SHORTHAND_QUERY)


class JavaScriptRenamer(BaseRenamer):
    """Renames the internal identifiers of a JavaScript file."""

    language = Language.JAVASCRIPT

    def facts(self, parsed: ParsedFile) -> SourceFacts:
        """The byte offsets of the shorthand properties and patterns."""
        if parsed.tree is None:
            raise PseudonymError("a file without a syntax tree is not renamed")
        captures = QueryCursor(_shorthand_query(self.language)).captures(parsed.tree.root_node)
        return SourceFacts(
            shorthand_starts=frozenset(node.start_byte for node in captures.get("shorthand", [])),
            specifier_starts=frozenset(
                node.start_byte + 1
                for node in captures.get("specifier", [])  # past the quote
            ),
        )

    def identifier_edits(
        self, name: str, token: str, start: int, end: int, facts: SourceFacts
    ) -> list[RenameEdit]:
        """A shorthand is expanded to ``key: token``; a private field keeps its ``#``."""
        if start in facts.shorthand_starts:
            return [RenameEdit(start, end, f"{name}: {token}", EditReason.SHORTHAND_KEY)]
        if name.startswith("#"):
            return [RenameEdit(start, end, f"#{token}", EditReason.IDENTIFIER)]
        return [RenameEdit(start, end, token, EditReason.IDENTIFIER)]


class TypeScriptRenamer(JavaScriptRenamer):
    """Renames the internal identifiers of a TypeScript file."""

    language = Language.TYPESCRIPT
