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
from codekavach.parsing.scopes import ScopeBuilder
from codekavach.parsing.spec import REGISTRY, NodeKind, NodeKindMap
from codekavach.parsing.specs.python_scopes import bind_python

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
    # In Python a class body sees its own names (``y = x + 1`` after ``x = 1``), its methods do not.
    class_body_sees_members = True

    def bind_scopes(self, root: object, builder: ScopeBuilder) -> None:
        """Feed ``builder`` the scopes and identifier occurrences of the tree rooted at ``root``.

        Not part of the ``LanguageSpec`` protocol; ``codekavach.parsing.symbols`` calls it
        through ``getattr`` so that a language without scoping rules simply has no such method.
        """
        bind_python(cast(TSNode, root), builder)

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


_GROUP_PARENTS = frozenset({"concatenated_string", "binary_operator", "parenthesized_expression"})


def _is_plus(node: TSNode) -> bool:
    if node.type != "binary_operator":
        return False
    operator = node.child_by_field_name("operator")
    return operator is not None and operator.type == "+"


def _plus_literals(node: TSNode, found: list[TSNode]) -> None:
    """The string literals of a ``+`` chain, in source order; calls and names are not entered."""
    if node.type == "string":
        found.append(node)
    elif node.type == "concatenated_string":
        found.extend(child for child in node.children if child.type == "string")
    elif node.type == "parenthesized_expression" or _is_plus(node):
        for child in node.children:
            _plus_literals(child, found)


def _group_top(string_node: TSNode) -> TSNode:
    """The outermost node of the ``+`` chain or adjacent-literal group ``string_node`` is in."""
    top = string_node
    if top.parent is not None and top.parent.type == "concatenated_string":
        top = top.parent
    while top.parent is not None:
        parent = top.parent
        if _is_plus(parent):
            top = parent
        elif (
            parent.type == "parenthesized_expression"
            and parent.parent is not None
            and _is_plus(parent.parent)
        ):
            top = parent.parent
        else:
            break
    return top


def _concatenation_text(string_node: TSNode) -> tuple[str | None, TSNode]:
    """The joined content of the literals that build one value, and the node to climb from.

    Three shapes join their pieces (E09-FU-SQL-PIECES): adjacent literals (``"a" "b"``), a ``+``
    chain (``"a" + x + "b"``) and the pieces of one f-string around its interpolations. The text
    is ``None`` when the literal has only one piece. The node is where the enclosing call or
    assignment is looked up from.
    """
    parent = string_node.parent
    if (parent is None or parent.type not in _GROUP_PARENTS) and not any(
        child.type == "interpolation" for child in string_node.children
    ):
        return None, string_node  # the common case: a plain literal on its own
    top = _group_top(string_node)
    literals: list[TSNode] = []
    _plus_literals(top, literals)
    pieces = [piece for literal in literals for piece in _string_fragments(literal)]
    if len(pieces) < 2:
        return None, string_node
    return "".join(pieces), top


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
    joined_text, base = _concatenation_text(string_node)
    callee_text, assignment_target = _enclosing_call_or_assignment(base)
    return LiteralContext(
        callee_text=callee_text, assignment_target=assignment_target, joined_text=joined_text
    )


REGISTRY.register(PythonSpec())
