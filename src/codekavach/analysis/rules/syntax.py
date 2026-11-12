"""Syntax helpers the native matchers share, over tree-sitter nodes for Python and JavaScript.

Owning epic: E13. MVP; extended by E16, whose rule language replaces these predicates.

Everything here is syntactic and says so: a "request-derived" value is a name that is a parameter
of the enclosing function, a value read from ``request`` or ``req``, or a local variable assigned
from one of those. No data-flow or taint analysis happens here (that is a later epic); the helpers
answer the small questions a matcher's explicit sink list and safe-form predicate need.
"""

import re
from collections.abc import Iterator
from typing import Final

from tree_sitter import Node

FUNCTION_TYPES: Final = frozenset(
    {
        "function_definition",
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "generator_function",
        "arrow_function",
        "method_definition",
        "method_declaration",
        "method",
        "singleton_method",
        "local_function_statement",
        "anonymous_function",
    }
)
CALL_TYPES: Final = frozenset(
    {
        "call",
        "call_expression",
        "function_call_expression",
        "member_call_expression",
        "invocation_expression",
    }
)
ASSIGNMENT_TYPES: Final = frozenset({"assignment", "variable_declarator", "assignment_expression"})
IDENTIFIER_TYPES: Final = frozenset(
    {
        "identifier",
        "property_identifier",
        "shorthand_property_identifier",
        "name",
        "simple_identifier",
    }
)
REQUEST_ROOTS: Final = frozenset(
    {
        "request", "req", "flask", "ctx", "event",
        "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES",
        "params", "cookies", "Request", "HttpContext",
    }
)  # fmt: skip
# Parameters that are never user input: the receiver, the response and the database handles.
NON_INPUT_PARAMETERS: Final = frozenset(
    {
        "self", "cls", "res", "response", "resp", "reply", "next", "conn", "connection", "cursor",
        "cur", "db", "logger", "log", "app", "router", "config", "settings",
    }
)  # fmt: skip
MAX_RESOLVE_DEPTH: Final = 4
STRING_KINDS: Final = frozenset(
    {
        "string",
        "template_string",
        "concatenated_string",
        "encapsed_string",
        "interpolated_string_expression",
        "string_literal",
    }
)
INTERPOLATION_TYPES: Final = frozenset(
    {"interpolation", "template_substitution", "interpolated_expression"}
)
BINARY_KINDS: Final = frozenset(
    {"binary_operator", "binary_expression", "binary", "additive_expression"}
)
CONCAT_OPERATORS: Final = frozenset({"+", "%", "."})
ESCAPE_NAMES: Final = frozenset(
    {
        "escape", "escape_html", "escapehtml", "html_escape", "htmlescape", "sanitize",
        "sanitise", "sanitize_html", "sanitizehtml", "clean", "encodeuricomponent", "xss_clean",
        "quote", "quote_plus", "shellescape", "escapeshellarg", "escape_string", "encode_html",
    }
)  # fmt: skip
_NUMBERISH: Final = frozenset(
    {"int", "float", "str_to_int", "number", "parseint", "parsefloat", "len"}
)
_WORD: Final = re.compile(r"[A-Za-z0-9_]+")
_STATIC_LITERALS: Final = frozenset(
    {"integer", "float", "number", "true", "false", "none", "null", "undefined", "comment"}
)


def text_of(node: Node) -> str:
    """The source text of ``node``."""
    return node.text.decode("utf-8", errors="replace") if node.text is not None else ""


def last_segment(name: str | None) -> str:
    """The part of a dotted name after the last dot (``cur.execute`` gives ``execute``)."""
    return "" if not name else name.rsplit(".", 1)[-1]


def dotted(node: Node | None) -> str | None:
    """The dotted name of an identifier or attribute chain, or ``None`` for anything else."""
    if node is None:
        return None
    if node.type in IDENTIFIER_TYPES:
        return text_of(node)
    if node.type in {"attribute", "member_expression"}:
        owner = dotted(node.child_by_field_name("object"))
        member = node.child_by_field_name("attribute") or node.child_by_field_name("property")
        if owner is None or member is None:
            return None
        return f"{owner}.{text_of(member)}"
    return None


def callee_name(call: Node) -> str | None:
    """The dotted callee of a call node (``subprocess.run``), or ``None``."""
    return dotted(call.child_by_field_name("function"))


def call_arguments(call: Node) -> tuple[list[Node], dict[str, Node]]:
    """The positional arguments and the keyword arguments (or options-object pairs) of a call."""
    holder = call.child_by_field_name("arguments")
    positional: list[Node] = []
    keywords: dict[str, Node] = {}
    if holder is None:
        return positional, keywords
    for child in holder.named_children:
        if child.type == "comment":
            continue
        if child.type == "keyword_argument":
            name, value = child.child_by_field_name("name"), child.child_by_field_name("value")
            if name is not None and value is not None:
                keywords[text_of(name)] = value
        elif child.type == "object":
            for pair in child.named_children:
                key, value = pair.child_by_field_name("key"), pair.child_by_field_name("value")
                if pair.type == "pair" and key is not None and value is not None:
                    keywords[text_of(key).strip("'\"")] = value
            positional.append(child)
        else:
            positional.append(child)
    return positional, keywords


def walk(node: Node) -> Iterator[Node]:
    """Every named node under ``node`` (itself included), parents before children."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def identifiers_in(node: Node) -> list[str]:
    """The names of every identifier under ``node``, in source order."""
    return [text_of(item) for item in walk(node) if item.type in IDENTIFIER_TYPES]


def enclosing_function(node: Node) -> Node | None:
    """The innermost function that contains ``node``, or ``None`` at module level."""
    current = node.parent
    while current is not None:
        if current.type in FUNCTION_TYPES:
            return current
        current = current.parent
    return None


def function_name(function: Node) -> str | None:
    """The declared name of ``function`` (a variable-bound arrow function gets the variable's)."""
    name = function.child_by_field_name("name")
    if name is not None:
        return text_of(name)
    parent = function.parent
    if parent is not None and parent.type == "variable_declarator":
        bound = parent.child_by_field_name("name")
        return text_of(bound) if bound is not None else None
    return None


def function_parameters(function: Node) -> set[str]:
    """The parameter names of ``function`` that can carry caller input."""
    holder = function.child_by_field_name("parameters") or function.child_by_field_name("parameter")
    if holder is None:  # Kotlin's grammar has no field names
        holder = next(
            (c for c in function.named_children if c.type == "function_value_parameters"), None
        )
    if holder is None:
        return set()
    if holder.type in IDENTIFIER_TYPES:
        return {text_of(holder)}
    names: set[str] = set()
    for child in holder.named_children:
        target = child
        if child.type in {"default_parameter", "typed_parameter", "typed_default_parameter"}:
            target = child.child_by_field_name("name") or (
                child.named_children[0] if child.named_children else child
            )
        elif child.type in {"assignment_pattern", "rest_pattern"}:
            target = child.child_by_field_name("left") or (
                child.named_children[0] if child.named_children else child
            )
        elif child.type in {"simple_parameter", "property_promotion_parameter", "parameter"}:
            target = child.child_by_field_name("name") or next(
                (n for n in child.named_children if n.type in IDENTIFIER_TYPES | {"variable_name"}),
                child,
            )
            if target.type == "variable_name":
                target = next((n for n in target.named_children if n.type == "name"), target)
        elif child.type in {"list_splat_pattern", "dictionary_splat_pattern"}:
            target = child.named_children[0] if child.named_children else child
        if target.type in IDENTIFIER_TYPES:
            names.add(text_of(target))
        elif target.type == "object_pattern":
            names.update(identifiers_in(target))
    return names - NON_INPUT_PARAMETERS


def assignments_of(scope: Node, name: str, *, module_level: bool = False) -> list[Node]:
    """The right-hand sides assigned to ``name`` in ``scope`` (module level: statements only)."""
    found: list[Node] = []
    nodes = (
        (statement for child in scope.named_children for statement in _statement_nodes(child))
        if module_level
        else walk(scope)
    )
    for node in nodes:
        if node.type not in ASSIGNMENT_TYPES:
            continue
        target = node.child_by_field_name("left") or node.child_by_field_name("name")
        value = node.child_by_field_name("right") or node.child_by_field_name("value")
        if target is not None and value is not None and dotted(target) == name:
            found.append(value)
    return found


def _statement_nodes(statement: Node) -> Iterator[Node]:
    yield statement
    if statement.type in {"expression_statement", "lexical_declaration", "variable_declaration"}:
        yield from statement.named_children


def is_static_string(node: Node) -> bool:
    """A string with no interpolation: a plain literal, adjacent literals, a plain template."""
    if node.type in {
        "string",
        "encapsed_string",
        "interpolated_string_expression",
        "string_literal",
    }:
        return all(
            child.type not in INTERPOLATION_TYPES | {"variable_name", "interpolated_identifier"}
            for child in node.named_children
        )
    if node.type == "template_string":
        return all(child.type != "template_substitution" for child in node.named_children)
    if node.type == "concatenated_string":
        return all(is_static_string(child) for child in node.named_children)
    return False


def is_literal(node: Node) -> bool:
    """A value with no variable part: a static string, a number, a boolean or null."""
    if node.type in _STATIC_LITERALS or is_static_string(node):
        return True
    if node.type == "parenthesized_expression" and node.named_children:
        return is_literal(node.named_children[0])
    if node.type in {"tuple", "list", "array"}:
        return all(is_literal(child) for child in node.named_children)
    return False


def _operator(node: Node) -> str:
    operator = node.child_by_field_name("operator")
    if operator is None:  # Kotlin's additive_expression has the operator as an unnamed child
        operator = next((c for c in node.children if not c.is_named and not c.is_extra), None)
    return text_of(operator) if operator is not None else ""


def string_parts(node: Node) -> list[Node] | None:
    """The non-literal operands that go into a string built at run time, or ``None``.

    ``None`` means ``node`` is not a string-building expression at all (an identifier, a call to
    something else). An empty list is a string made only of literals. A formatted string, a
    ``+`` or ``%`` chain with a string operand, ``.format(...)`` and ``.concat(...)`` are the
    building forms.
    """
    kind = node.type
    if kind in STRING_KINDS:
        parts: list[Node] = []
        for child in node.named_children:
            if child.type in {"variable_name", "interpolated_identifier"}:
                parts.append(child)  # PHP "x$v" and Kotlin "x$v": the variable is the child
            elif child.type in INTERPOLATION_TYPES:
                inner = child.child_by_field_name("expression") or (
                    child.named_children[0] if child.named_children else None
                )
                if inner is not None:
                    parts.append(inner)
            elif kind == "concatenated_string":
                parts.extend(string_parts(child) or [])
        return parts
    if kind == "parenthesized_expression" and node.named_children:
        return string_parts(node.named_children[0])
    if kind in BINARY_KINDS and _operator(node) in CONCAT_OPERATORS:
        return _chain_parts(node)
    if kind in CALL_TYPES:
        function = node.child_by_field_name("function")
        member = function.child_by_field_name("attribute") if function is not None else None
        member = member or (function.child_by_field_name("property") if function else None)
        owner = function.child_by_field_name("object") if function is not None else None
        if member is not None and owner is not None and text_of(member) in {"format", "concat"}:
            if string_parts(owner) is None:
                return None
            args, _ = call_arguments(node)
            return [item for item in args if not is_literal(item)] + (string_parts(owner) or [])
    return None


def _chain_parts(node: Node) -> list[Node] | None:
    """The operands of a ``+`` or ``%`` chain, or ``None`` when no operand is a string."""
    operands: list[Node] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in BINARY_KINDS and _operator(current) in CONCAT_OPERATORS:
            left, right = current.child_by_field_name("left"), current.child_by_field_name("right")
            stack.extend(item for item in (right, left) if item is not None)
        else:
            operands.append(current)
    operands.reverse()
    if not any(string_parts(item) is not None for item in operands):
        return None
    parts: list[Node] = []
    for item in operands:
        nested = string_parts(item)
        if nested is not None:
            parts.extend(nested)
        elif (
            item.type in {"tuple", "parenthesized_expression", "list"}
            and node.type == "binary_operator"
        ):
            parts.extend(child for child in item.named_children if not is_literal(child))
        elif not is_literal(item):
            parts.append(item)
    return parts


def static_text(node: Node) -> str:
    """Every static fragment of a string expression, joined."""
    return "".join(
        text_of(item) for item in walk(node) if item.type in {"string_content", "string_fragment"}
    )


def is_escaped(part: Node) -> bool:
    """True when ``part`` is a call to an escaping, quoting or number-coercing function."""
    if part.type not in CALL_TYPES:
        return False
    name = last_segment(callee_name(part)).lower()
    return name in ESCAPE_NAMES or name in _NUMBERISH


def resolve_string(node: Node, function: Node | None, root: Node, depth: int = 0) -> Node:
    """Follow an identifier to the expression it was assigned (one assignment, a few hops)."""
    current = node
    while current.type == "identifier" and depth < MAX_RESOLVE_DEPTH:
        name = text_of(current)
        values = assignments_of(function, name) if function is not None else []
        if not values:
            values = assignments_of(root, name, module_level=True)
        if len(values) != 1:
            break
        current, depth = values[0], depth + 1
    return current


def is_request_derived(expression: Node, function: Node | None, root: Node, depth: int = 0) -> bool:
    """Whether ``expression`` uses caller input: a parameter, ``request`` data or a local."""
    parameters = function_parameters(function) if function is not None else set()
    for item in walk(expression):
        if item.type not in IDENTIFIER_TYPES or item.parent is None:
            continue
        if item.parent.type in {"attribute", "member_expression", "member_access_expression"}:
            owner = item.parent.child_by_field_name("object") or item.parent.child_by_field_name(
                "expression"
            )
            if owner is not None and owner.id != item.id:
                continue  # an attribute name, not a variable
        name = text_of(item)
        if name in REQUEST_ROOTS or name in parameters:
            return True
        if depth < MAX_RESOLVE_DEPTH and function is not None:
            for value in assignments_of(function, name):
                if value.id != expression.id and is_request_derived(
                    value, function, root, depth + 1
                ):
                    return True
    return False


def words(text: str) -> set[str]:
    """The identifier-like words of ``text``, lower-cased."""
    return {word.lower() for word in _WORD.findall(text)}
