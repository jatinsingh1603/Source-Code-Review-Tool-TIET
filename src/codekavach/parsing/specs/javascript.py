"""The JavaScript and TypeScript ``LanguageSpec``s (E07-02).

Owning epic: E07.

Registers both at import time, so merely importing ``codekavach.parsing`` makes
``SpecRegistry.get`` succeed for ``Language.JAVASCRIPT`` and ``Language.TYPESCRIPT``.
``TypeScriptSpec`` subclasses ``JavaScriptSpec`` and only widens ``node_kinds()``: the pinned
grammar's node-type vocabulary has no separate ``field_identifier`` (unlike the issue's own
technical note), so the extra identifier-like type it adds is ``type_identifier`` only.
"""

from typing import cast

from tree_sitter import Node as TSNode

from codekavach.core.models import Language
from codekavach.parsing.literals import LiteralContext
from codekavach.parsing.spec import REGISTRY, NodeKind, NodeKindMap

# ECMAScript reserved words (ECMA-262); not grammar node types, just the vocabulary a reviewer
# would recognise as "not a renameable identifier".
KEYWORDS = frozenset(
    {
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "enum",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "new",
        "null",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "let",
        "static",
        "async",
        "get",
        "set",
        "of",
        "as",
        "from",
    }
)

# Common global and Node/browser builtins a reviewer recognises; not exhaustive, kept because
# sources, sinks and sanitisers must stay recognisable (docs/ARCHITECTURE.md section 6.2 step 4).
BUILTINS = frozenset(
    {
        "console",
        "window",
        "document",
        "process",
        "require",
        "module",
        "exports",
        "global",
        "globalThis",
        "Object",
        "Array",
        "String",
        "Number",
        "Boolean",
        "Function",
        "Symbol",
        "Map",
        "Set",
        "WeakMap",
        "WeakSet",
        "Promise",
        "Proxy",
        "Reflect",
        "JSON",
        "Math",
        "Date",
        "RegExp",
        "Error",
        "TypeError",
        "RangeError",
        "SyntaxError",
        "ReferenceError",
        "EvalError",
        "URIError",
        "Infinity",
        "NaN",
        "undefined",
        "parseInt",
        "parseFloat",
        "isNaN",
        "isFinite",
        "encodeURIComponent",
        "decodeURIComponent",
        "encodeURI",
        "decodeURI",
        "setTimeout",
        "setInterval",
        "clearTimeout",
        "clearInterval",
        "fetch",
        "Buffer",
        "Int8Array",
        "Uint8Array",
        "Float32Array",
        "Float64Array",
        "ArrayBuffer",
        "BigInt",
    }
)

# Node types with their own "name" field, as plain name lookups.
_NAMED_CONTAINERS = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "class_declaration",
        "method_definition",
        "interface_declaration",
        "type_alias_declaration",
        "enum_declaration",
    }
)
# Anonymous function/class expressions: a name is recovered from how the expression is used.
_ANONYMOUS_CONTAINERS = frozenset(
    {"arrow_function", "function_expression", "generator_function", "class"}
)
_ALL_CONTAINERS = _NAMED_CONTAINERS | _ANONYMOUS_CONTAINERS


def _field_text(node: TSNode, field: str) -> str | None:
    child = node.child_by_field_name(field)
    if child is None or child.text is None:
        return None
    return child.text.decode("utf-8", errors="replace")


def _name_of(node: TSNode) -> str | None:
    """The name of a function or class container, recovered from context when it is anonymous."""
    direct = _field_text(node, "name")
    if direct is not None:
        return direct
    parent = node.parent
    if parent is None:
        return None
    if parent.type == "variable_declarator":
        return _field_text(parent, "name")
    if parent.type == "pair":
        return _field_text(parent, "key")
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None and left.type == "identifier":
            return _field_text(parent, "left")
    return None


def enclosing_symbol(node: TSNode) -> str | None:
    """Walk up from ``node`` to every enclosing named function or class container."""
    if node.type == "comment":
        return None
    names: list[str] = []
    current = node.parent
    while current is not None:
        if current.type in _ALL_CONTAINERS:
            name = _name_of(current)
            if name is not None:
                names.append(name)
        current = current.parent
    return ".".join(reversed(names)) if names else None


class JavaScriptSpec:
    """The ``LanguageSpec`` for JavaScript."""

    language = Language.JAVASCRIPT
    grammar_version = "tree-sitter-language-pack"
    keywords = KEYWORDS
    builtins = BUILTINS

    def node_kinds(self) -> NodeKindMap:
        """Map each ``NodeKind`` to the JavaScript grammar's node-type names that mean it."""
        return {
            NodeKind.FUNCTION: frozenset(
                {
                    "function_declaration",
                    "generator_function_declaration",
                    "function_expression",
                    "arrow_function",
                    "generator_function",
                }
            ),
            NodeKind.CLASS: frozenset({"class_declaration", "class"}),
            NodeKind.METHOD: frozenset({"method_definition"}),
            NodeKind.CALL: frozenset({"call_expression"}),
            NodeKind.IMPORT: frozenset({"import_statement"}),
            NodeKind.ASSIGNMENT: frozenset({"assignment_expression", "variable_declarator"}),
            NodeKind.STRING: frozenset({"string_fragment", "regex_pattern"}),
            NodeKind.COMMENT: frozenset({"comment"}),
            NodeKind.IDENTIFIER: frozenset(
                {
                    "identifier",
                    "property_identifier",
                    "shorthand_property_identifier",
                    "shorthand_property_identifier_pattern",
                    "private_property_identifier",
                    "statement_identifier",
                }
            ),
            NodeKind.PARAMETER: frozenset({"formal_parameters", "required_parameter"}),
            NodeKind.FIELD: frozenset({"member_expression", "field_definition"}),
            NodeKind.DECORATOR: frozenset({"decorator"}),
            NodeKind.BLOCK: frozenset({"statement_block"}),
        }

    def enclosing_symbol(self, node: object, source: str) -> str | None:
        """The dotted name of the function or class ``node`` is nested in, if any."""
        return enclosing_symbol(cast(TSNode, node))

    def literal_context(self, node: object) -> LiteralContext:
        """The classifier context for ``node`` (a ``string_fragment`` or ``regex_pattern``).

        Not part of the ``LanguageSpec`` protocol; ``codekavach.parsing.parser`` calls it
        through ``getattr``.
        """
        return literal_context(cast(TSNode, node))


class TypeScriptSpec(JavaScriptSpec):
    """The ``LanguageSpec`` for TypeScript: JavaScript plus the type-level constructs.

    ``interface_declaration``, ``type_alias_declaration`` and ``enum_declaration`` are named
    type-level containers, grouped under ``NodeKind.CLASS`` alongside ``class_declaration``
    rather than given their own kind: nothing in this issue's own extractors (``identifiers``,
    ``string_literals``, ``comments``) distinguishes them from a class, and inventing a kind
    with no consumer risks guessing wrong about what the scope resolver (E07-03) actually
    needs. ``type_annotation`` and ``abstract_method_signature`` are structural TypeScript
    syntax, not a name or a definition, and are deliberately left unmapped for the same reason.
    """

    language = Language.TYPESCRIPT

    def node_kinds(self) -> NodeKindMap:
        """``JavaScriptSpec.node_kinds()``, widened with TypeScript's type-level containers."""
        mapping = dict(super().node_kinds())
        mapping[NodeKind.IDENTIFIER] = mapping[NodeKind.IDENTIFIER] | frozenset({"type_identifier"})
        mapping[NodeKind.CLASS] = mapping[NodeKind.CLASS] | frozenset(
            {"interface_declaration", "type_alias_declaration", "enum_declaration"}
        )
        return mapping


def _fragments_of(string_node: TSNode) -> list[str]:
    """The ``string_fragment`` text of one ``string``/``template_string`` node, in source order."""
    return [
        child.text.decode("utf-8", errors="replace")
        for child in string_node.children
        if child.type == "string_fragment" and child.text is not None
    ]


def _is_plus_binary(node: TSNode) -> bool:
    if node.type != "binary_expression":
        return False
    operator = node.child_by_field_name("operator")
    return operator is not None and operator.type == "+"


def _plus_chain_text(leaf: TSNode) -> str | None:
    """The joined fragment text of every string/template literal in a ``+`` chain, or ``None``.

    ``None`` when ``leaf`` is not part of a ``+`` ``binary_expression`` chain.
    """
    parent = leaf.parent
    if parent is None or not _is_plus_binary(parent):
        return None
    top = parent
    while top.parent is not None and _is_plus_binary(top.parent):
        top = top.parent
    literals: list[TSNode] = []
    stack = [top]
    while stack:
        current = stack.pop()
        if current.type in ("string", "template_string"):
            literals.append(current)
            continue
        stack.extend(reversed(current.children))
    literals.sort(key=lambda n: n.start_byte)
    parts = [fragment for node in literals for fragment in _fragments_of(node)]
    return "".join(parts) if parts else None


def _callee_of_call_or_new(call: TSNode) -> str | None:
    """The callee text of a ``call_expression`` or ``new_expression``, or ``None``."""
    if call.type == "call_expression":
        return _field_text(call, "function")
    if call.type == "new_expression":
        constructor = _field_text(call, "constructor")
        return None if constructor is None else "new " + constructor
    return None


def _enclosing_call_or_assignment(leaf: TSNode) -> tuple[str | None, str | None]:
    """The ``(callee_text, assignment_target)`` of the call argument or assignment ``leaf``."""
    ancestor = leaf.parent
    if ancestor is None:
        return None, None
    if ancestor.type == "arguments" and ancestor.parent is not None:
        return _callee_of_call_or_new(ancestor.parent), None
    if ancestor.type == "variable_declarator":
        return None, _field_text(ancestor, "name")
    if ancestor.type == "assignment_expression":
        left = ancestor.child_by_field_name("left")
        target = (
            _field_text(ancestor, "left")
            if left is not None and left.type == "identifier"
            else None
        )
        return None, target
    return None, None


def literal_context(node: TSNode) -> LiteralContext:
    """The classifier context for ``node`` (a ``string_fragment`` or ``regex_pattern``)."""
    if node.type == "regex_pattern":
        regex_node = node.parent  # "regex"
        callee_text, assignment_target = (
            _enclosing_call_or_assignment(regex_node) if regex_node is not None else (None, None)
        )
        return LiteralContext(
            callee_text=callee_text, assignment_target=assignment_target, is_regex_literal=True
        )
    string_node = node.parent
    if string_node is None or string_node.type not in ("string", "template_string"):
        string_node = node
    joined_text = _plus_chain_text(string_node)
    # _plus_chain_text returns non-None only because string_node.parent is a "+"
    # binary_expression; climb to the top of that chain for the enclosing lookup below.
    base = string_node
    if joined_text is not None:
        while base.parent is not None and _is_plus_binary(base.parent):
            base = base.parent
    callee_text, assignment_target = _enclosing_call_or_assignment(base)
    return LiteralContext(
        callee_text=callee_text, assignment_target=assignment_target, joined_text=joined_text
    )


REGISTRY.register(JavaScriptSpec())
REGISTRY.register(TypeScriptSpec())
