"""The Python ``LanguageSpec`` (E07-02).

Owning epic: E07.

Registers at import time, so merely importing ``codekavach.parsing`` makes
``SpecRegistry.get(Language.PYTHON)`` succeed. Python's grammar uses exactly one node type,
``identifier``, for every name occurrence (definitions, references, parameters, attributes,
keyword-argument names, match targets, aliases), which is why ``node_kinds()`` maps
``NodeKind.IDENTIFIER`` to a single-entry set.
"""

import builtins
import keyword
from typing import cast

from tree_sitter import Node as TSNode

from codekavach.core.models import Language
from codekavach.parsing.literals import LiteralContext
from codekavach.parsing.spec import REGISTRY, NodeKind, NodeKindMap

# Built-in functions, exceptions and constants (True/False/None, NotImplemented, Ellipsis);
# dunder module attributes (__name__, __loader__, ...) are excluded, they are not identifiers a
# contributor writes.
BUILTINS = frozenset(name for name in dir(builtins) if not name.startswith("__"))

_NAMED_DEFINITIONS = frozenset({"function_definition", "class_definition"})


class PythonSpec:
    """The ``LanguageSpec`` for Python."""

    language = Language.PYTHON
    grammar_version = "tree-sitter-language-pack"
    keywords = frozenset(keyword.kwlist) | frozenset(keyword.softkwlist)
    builtins = BUILTINS

    def node_kinds(self) -> NodeKindMap:
        """Map each ``NodeKind`` to the Python grammar's node-type names that mean it."""
        return {
            NodeKind.FUNCTION: frozenset({"function_definition"}),
            NodeKind.CLASS: frozenset({"class_definition"}),
            NodeKind.CALL: frozenset({"call"}),
            NodeKind.IMPORT: frozenset({"import_statement", "import_from_statement"}),
            NodeKind.ASSIGNMENT: frozenset({"assignment", "augmented_assignment"}),
            NodeKind.STRING: frozenset({"string_content"}),
            NodeKind.COMMENT: frozenset({"comment"}),
            NodeKind.IDENTIFIER: frozenset({"identifier"}),
            NodeKind.PARAMETER: frozenset(
                {"parameters", "default_parameter", "typed_parameter", "typed_default_parameter"}
            ),
            NodeKind.FIELD: frozenset({"attribute"}),
            NodeKind.DECORATOR: frozenset({"decorator"}),
            NodeKind.BLOCK: frozenset({"block"}),
        }

    def enclosing_symbol(self, node: object, source: str) -> str | None:
        """The dotted name of the function or class ``node`` is nested in, if any."""
        return enclosing_symbol(cast(TSNode, node))

    def literal_context(self, node: object) -> LiteralContext:
        """The classifier context for the ``string_content`` node ``node``.

        Not part of the ``LanguageSpec`` protocol; ``codekavach.parsing.parser`` calls it
        through ``getattr`` so that a language without extra context to add simply has no such
        method.
        """
        return literal_context(cast(TSNode, node))


def _name_of(node: TSNode) -> str | None:
    """The ``name`` field's text, for a function or class definition node."""
    child = node.child_by_field_name("name")
    if child is None or child.text is None:
        return None
    return child.text.decode("utf-8", errors="replace")


def enclosing_symbol(node: TSNode) -> str | None:
    """Walk up from ``node`` to every enclosing function/class, returning a dotted name."""
    if node.type == "comment":
        return None
    names: list[str] = []
    current = node.parent
    while current is not None:
        if current.type in _NAMED_DEFINITIONS:
            name = _name_of(current)
            if name is not None:
                names.append(name)
        current = current.parent
    return ".".join(reversed(names)) if names else None


def _string_fragments(string_node: TSNode) -> list[str]:
    """The ``string_content`` text of one ``string`` node, in source order."""
    return [
        child.text.decode("utf-8", errors="replace")
        for child in string_node.children
        if child.type == "string_content" and child.text is not None
    ]


def _concatenation_text(string_node: TSNode) -> str | None:
    """The joined content of an adjacent-literal concatenation group, or ``None``.

    ``None`` when ``string_node`` is not part of a ``concatenated_string``.
    """
    parent = string_node.parent
    if parent is None or parent.type != "concatenated_string":
        return None
    parts: list[str] = []
    for child in parent.children:
        if child.type == "string":
            parts.extend(_string_fragments(child))
    return "".join(parts)


def _enclosing_call_or_assignment(start: TSNode) -> tuple[str | None, str | None]:
    """The ``(callee_text, assignment_target)`` of the call argument or assignment ``start`` is in.

    Skips a wrapping ``parenthesized_expression`` and a ``%``/``+`` ``binary_operator`` (the
    ``"..." % value`` and ``"..." + value`` idioms).
    """
    ancestor = start.parent
    while ancestor is not None and ancestor.type in ("parenthesized_expression", "binary_operator"):
        ancestor = ancestor.parent
    if ancestor is None:
        return None, None
    if ancestor.type == "argument_list":
        call = ancestor.parent
        if call is not None and call.type == "call":
            function = call.child_by_field_name("function")
            if function is not None and function.text is not None:
                return function.text.decode("utf-8", errors="replace"), None
    elif ancestor.type == "assignment":
        left = ancestor.child_by_field_name("left")
        if left is not None and left.type == "identifier" and left.text is not None:
            return None, left.text.decode("utf-8", errors="replace")
    return None, None


def literal_context(node: TSNode) -> LiteralContext:
    """The classifier context for ``node`` (a ``string_content`` node)."""
    string_node = node.parent if node.parent is not None and node.parent.type == "string" else node
    joined_text = _concatenation_text(string_node)
    base = string_node.parent if joined_text is not None else string_node
    callee_text, assignment_target = (
        _enclosing_call_or_assignment(base) if base is not None else (None, None)
    )
    return LiteralContext(
        callee_text=callee_text, assignment_target=assignment_target, joined_text=joined_text
    )


REGISTRY.register(PythonSpec())
