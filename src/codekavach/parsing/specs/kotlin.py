"""The Kotlin ``LanguageSpec`` (E07-05b).

Owning epic: E07.

Registers at import time. Kotlin's grammar has no field names, so declarations are found by
position: the name of a class is its first ``type_identifier``, the name of a function or a
parameter its first ``simple_identifier``. ``a.b`` is a ``navigation_expression`` whose member
sits in a ``navigation_suffix``. Scoping is bound by the table-driven ``generic_scopes`` walk.
"""

from typing import Final

from codekavach.core.models import Language
from codekavach.parsing.spec import REGISTRY, NodeKind
from codekavach.parsing.specs.c_style_literals import Shapes
from codekavach.parsing.specs.generic import TableSpec
from codekavach.parsing.specs.generic_scopes import (
    Rules,
    all_children,
    first_child,
    leaves,
    no_names,
)

KEYWORDS: Final = frozenset(
    {
        "as", "break", "class", "continue", "do", "else", "false", "for", "fun", "if", "in",
        "interface", "is", "null", "object", "package", "return", "super", "this", "throw", "true",
        "try", "typealias", "typeof", "val", "var", "when", "while", "by", "catch", "constructor",
        "delegate", "dynamic", "field", "file", "finally", "get", "import", "init", "param",
        "property", "receiver", "set", "setparam", "value", "where", "abstract", "actual",
        "annotation", "companion", "const", "crossinline", "data", "enum", "expect", "external",
        "final", "infix", "inline", "inner", "internal", "lateinit", "noinline", "open", "operator",
        "out", "override", "private", "protected", "public", "reified", "sealed", "suspend",
        "tailrec", "vararg", "it",
    }
)  # fmt: skip

BUILTINS: Final = frozenset(
    {
        "Any", "Nothing", "Unit", "Int", "Long", "Short", "Byte", "Float", "Double", "Boolean",
        "Char", "String", "Array", "List", "MutableList", "Map", "MutableMap", "Set", "MutableSet",
        "Pair", "Triple", "Sequence", "Iterable", "Collection", "println", "print", "listOf",
        "mutableListOf", "mapOf", "mutableMapOf", "setOf", "arrayOf", "emptyList", "require",
        "check", "error", "TODO", "lazy", "run", "let", "apply", "also", "with", "use",
    }
)  # fmt: skip

_NAMES: Final = frozenset({"simple_identifier", "type_identifier", "interpolated_identifier"})
_VALUE: Final = frozenset({"simple_identifier"})
_TYPE: Final = frozenset({"type_identifier"})


def _import_path(node):  # type: ignore[no-untyped-def]
    path = next((c for c in node.named_children if c.type == "identifier"), None)
    return leaves(path, _VALUE)


_RULES: Final = Rules(
    names=_NAMES,
    types={
        "class_declaration": first_child(_TYPE),
        "object_declaration": first_child(_TYPE),
        "companion_object": no_names,
        "type_alias": first_child(_TYPE),
    },
    functions={
        "function_declaration": first_child(_VALUE),
        "secondary_constructor": no_names,
        "anonymous_function": no_names,
    },
    lambdas=frozenset({"lambda_literal"}),
    blocks=frozenset({"for_statement", "while_statement", "catch_block", "when_expression"}),
    bodies=frozenset({"function_body"}),
    declarations={
        "parameter": (first_child(_VALUE), "parameter"),
        "class_parameter": (first_child(_VALUE), "field"),
        "variable_declaration": (first_child(_VALUE), "variable"),
        "enum_entry": (first_child(_VALUE), "constant"),
        "type_parameter": (first_child(_TYPE), "class"),
    },
    paths={
        "navigation_suffix": (all_children(_VALUE), "field"),
        "import_header": (_import_path, "module"),
        "package_header": (lambda n: leaves(n, _VALUE), "module"),
    },
    aliases={"import_alias": all_children(_TYPE)},
)

_SHAPES: Final = Shapes(
    literals=frozenset({"string_literal"}),
    content=frozenset({"string_content"}),
    binary="additive_expression",
    parenthesised="parenthesized_expression",
    call="call_expression",
    callee_field="function",
    arguments="value_arguments",
    assignments=frozenset({"property_declaration", "assignment"}),
)

_KINDS: Final = {
    NodeKind.FUNCTION: frozenset({"function_declaration", "lambda_literal", "anonymous_function"}),
    NodeKind.CLASS: frozenset({"class_declaration", "object_declaration", "companion_object"}),
    NodeKind.METHOD: frozenset({"function_declaration", "secondary_constructor"}),
    NodeKind.CALL: frozenset({"call_expression"}),
    NodeKind.IMPORT: frozenset({"import_header"}),
    NodeKind.ASSIGNMENT: frozenset({"property_declaration", "assignment"}),
    NodeKind.STRING: frozenset({"string_content"}),
    NodeKind.COMMENT: frozenset({"line_comment", "multiline_comment"}),
    NodeKind.IDENTIFIER: _NAMES,
    NodeKind.PARAMETER: frozenset({"function_value_parameters", "parameter", "class_parameter"}),
    NodeKind.FIELD: frozenset({"navigation_expression", "property_declaration"}),
    NodeKind.DECORATOR: frozenset({"annotation"}),
    NodeKind.BLOCK: frozenset({"statements", "function_body", "class_body"}),
}

REGISTRY.register(
    TableSpec(
        Language.KOTLIN,
        keywords=KEYWORDS,
        builtins=BUILTINS,
        kinds=_KINDS,
        rules=_RULES,
        shapes=_SHAPES,
        comment_types=frozenset({"line_comment", "multiline_comment"}),
    )
)
