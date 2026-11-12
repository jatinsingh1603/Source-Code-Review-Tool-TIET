"""Evaluating the ``where`` constraints of a pattern clause (E16-02).

Owning epic: E16. A constraint looks at the text or the syntax of what a metavariable matched.
Everything here is syntactic: ``is_constant`` knows literals and concatenations of literals, not
data flow, so an identifier is never constant even when it was assigned a literal.

``kind`` uses a small node-kind vocabulary that is the same across languages. The grammar-specific
node names behind it are listed below; a language that is not listed has no ``concatenation`` or
``interpolation`` and its ``call``, ``literal`` and ``identifier`` fall back to generic names.
"""

import re
from collections.abc import Callable, Mapping
from typing import Final

from tree_sitter import Node

from codekavach.analysis.rules.dsl import Constraint
from codekavach.analysis.rules.syntax import (
    enclosing_function,
    function_parameters,
    is_literal,
    is_request_derived,
    resolve_string,
    string_parts,
)

CALL_TYPES: Final = frozenset(
    {"call", "call_expression", "method_invocation", "invocation_expression", "function_call"}
)
ATTRIBUTE_TYPES: Final = frozenset(
    {
        "attribute",
        "member_expression",
        "field_access",
        "selector_expression",
        "member_access_expression",
    }
)
IDENTIFIER_TYPES: Final = frozenset(
    {"identifier", "property_identifier", "field_identifier", "type_identifier"}
)
STRING_TYPES: Final = frozenset(
    {
        "string",
        "string_literal",
        "concatenated_string",
        "interpreted_string_literal",
        "raw_string_literal",
        "template_string",
        "encapsed_string",
        "interpolated_string_expression",
    }
)
NUMBER_TYPES: Final = frozenset(
    {
        "integer",
        "float",
        "number",
        "number_literal",
        "char_literal",
        "decimal_integer_literal",
        "int_literal",
        "float_literal",
        "true",
        "false",
        "none",
        "null",
        "nil",
        "boolean",
    }
)
BINARY_TYPES: Final = frozenset(
    {"binary_operator", "binary_expression", "binary", "additive_expression"}
)
SUBSTITUTION_TYPES: Final = frozenset(
    {"interpolation", "template_substitution", "interpolated_expression", "interpolated_identifier"}
)
ARGUMENT_PARENTS: Final = frozenset({"argument_list", "arguments"})
PARENTHESES: Final = frozenset({"parenthesized_expression"})

Lookup = Callable[[str, Node], bool]


def normalised(node: Node) -> str:
    """The node's text with runs of whitespace collapsed, as the fingerprint algorithm does."""
    return " ".join((node.text or b"").decode("utf-8", errors="replace").split())


def _operator(node: Node) -> bytes:
    operator = node.child_by_field_name("operator")
    if operator is None:
        operator = next((c for c in node.children if not c.is_named and not c.is_extra), None)
    return (operator.text or b"") if operator is not None else b""


def _has_substitution(node: Node) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in SUBSTITUTION_TYPES or (
            current.type == "variable_name" and node.type == "encapsed_string"
        ):
            return True
        stack.extend(current.children)
    return False


def is_concatenation(node: Node) -> bool:
    """``a + b`` in a language that has a binary plus."""
    return node.type in BINARY_TYPES and _operator(node) in {b"+", b"."}


def is_interpolation(node: Node) -> bool:
    """An f-string or template string with a substitution, or ``"..." % x``."""
    if node.type in STRING_TYPES:
        return _has_substitution(node)
    if node.type in BINARY_TYPES and _operator(node) == b"%":
        left = node.child_by_field_name("left")
        return left is not None and left.type in STRING_TYPES
    return False


def is_constant(node: Node) -> bool:
    """True for literals and for concatenations and parenthesised forms made only of literals."""
    if node.type in NUMBER_TYPES:
        return True
    if node.type in STRING_TYPES:
        return not _has_substitution(node)
    if node.type in PARENTHESES:
        inner = [child for child in node.named_children if child.type != "comment"]
        return len(inner) == 1 and is_constant(inner[0])
    if is_concatenation(node):
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        return left is not None and right is not None and is_constant(left) and is_constant(right)
    return False


def _root(node: Node) -> Node:
    while node.parent is not None:
        node = node.parent
    return node


def is_parameter(node: Node) -> bool:
    """An identifier that names a parameter of the function it sits in."""
    if node.type not in IDENTIFIER_TYPES:
        return False
    function = enclosing_function(node)
    return function is not None and (node.text or b"").decode() in function_parameters(function)


def is_constant_binding(node: Node) -> bool:
    """A literal, or a name whose single assignment is a literal (a module constant)."""
    return is_literal(resolve_string(node, enclosing_function(node), _root(node)))


def is_request_input(node: Node) -> bool:
    """Request data, a parameter, or a local assigned from one (syntactic, not data flow)."""
    return is_request_derived(node, enclosing_function(node), _root(node))


def has_kind(node: Node, kind: str) -> bool:
    """Whether ``node`` is of the cross-language ``kind``."""
    tests: Mapping[str, Callable[[Node], bool]] = {
        "concatenation": is_concatenation,
        "interpolation": is_interpolation,
        "call": lambda n: n.type in CALL_TYPES,
        "literal": lambda n: n.type in STRING_TYPES | NUMBER_TYPES,
        "identifier": lambda n: n.type in IDENTIFIER_TYPES,
        "attribute": lambda n: n.type in ATTRIBUTE_TYPES,
        "argument": lambda n: n.parent is not None and n.parent.type in ARGUMENT_PARENTS,
        "parameter": is_parameter,
        "request_derived": is_request_input,
        "dynamic_string": lambda n: bool(string_parts(n)),
        "constant_binding": is_constant_binding,
    }
    test = tests.get(kind)
    return test(node) if test is not None else False


def literal_value(node: Node) -> str | None:
    """The text between the quotes of a simple string literal, else ``None``."""
    if node.type not in STRING_TYPES:
        return None
    text = (node.text or b"").decode("utf-8", errors="replace")
    match = re.fullmatch(r"[A-Za-z]{0,2}(\"\"\"|'''|\"|'|`)(.*)\1", text, re.DOTALL)
    return match.group(2) if match else None


def holds(  # noqa: PLR0911 - one return per condition kind
    constraint: Constraint,
    nodes: tuple[Node, ...],
    compiled: Mapping[str, "re.Pattern[str]"],
    catalogue: Lookup,
    inadequate: Lookup | None = None,
) -> bool:
    """Whether the bound ``nodes`` satisfy the single condition of ``constraint``.

    A variadic binding is checked as a whole for text conditions and node by node (all must hold)
    for syntactic ones. An empty binding satisfies nothing but ``not_regex``.
    """
    text = " ".join(normalised(node) for node in nodes)
    if constraint.regex is not None:
        pattern = compiled[constraint.regex]
        return any(pattern.search(candidate) for candidate in _texts(nodes, text))
    if constraint.not_regex is not None:
        pattern = compiled[constraint.not_regex]
        return not any(pattern.search(candidate) for candidate in _texts(nodes, text))
    if constraint.min_length is not None:
        values = [literal_value(node) for node in nodes]
        size = sum(
            len(v) if v is not None else len(normalised(n))
            for v, n in zip(values, nodes, strict=True)
        )
        return size >= constraint.min_length
    if not nodes:
        return False
    if constraint.kind is not None:
        return all(has_kind(node, constraint.kind) for node in nodes)
    if constraint.is_constant is not None:
        return all(is_constant(node) for node in nodes) == constraint.is_constant
    if constraint.equals is not None:
        return _equals(nodes, text, {constraint.equals})
    if constraint.one_of is not None:
        return _equals(nodes, text, set(constraint.one_of))
    if constraint.catalogue is not None:
        return all(catalogue(constraint.catalogue, node) for node in nodes)
    if constraint.inadequate_for is not None and inadequate is not None:
        return all(inadequate(constraint.inadequate_for, node) for node in nodes)
    return False


def _texts(nodes: tuple[Node, ...], text: str) -> list[str]:
    """The node text, plus the text of the value a lone local name was assigned (one hop chain)."""
    texts = [text]
    if len(nodes) == 1 and nodes[0].type in IDENTIFIER_TYPES:
        node = nodes[0]
        value = resolve_string(node, enclosing_function(node), _root(node))
        if value.id != node.id:
            texts.append(normalised(value))
    return texts


def _equals(nodes: tuple[Node, ...], text: str, wanted: set[str]) -> bool:
    if text in wanted:
        return True
    values = [literal_value(node) for node in nodes]
    return len(nodes) == 1 and values[0] is not None and values[0] in wanted
