"""The C++ ``LanguageSpec`` (E07-05b).

Owning epic: E07.

Registers at import time; the scoping rules are in ``c_family``. A namespace shares the enclosing
scope, a ``Type::name`` qualified name's last segment is an external member, and a lambda opens a
function scope.
"""

from typing import Final

from codekavach.core.models import Language
from codekavach.parsing.spec import REGISTRY, NodeKind
from codekavach.parsing.specs.c_family import (
    CPP_BUILTINS,
    CPP_KEYWORDS,
    CPP_RULES,
    definition_names,
)
from codekavach.parsing.specs.c_style_literals import Shapes
from codekavach.parsing.specs.generic import TableSpec

_SHAPES: Final = Shapes(
    literals=frozenset({"string_literal", "concatenated_string", "raw_string_literal"}),
    content=frozenset({"string_content", "raw_string_content"}),
    binary="binary_expression",
    parenthesised="parenthesized_expression",
    call="call_expression",
    callee_field="function",
    arguments="argument_list",
    assignments=frozenset({"init_declarator", "assignment_expression"}),
)

_KINDS: Final = {
    NodeKind.FUNCTION: frozenset({"function_definition", "lambda_expression"}),
    NodeKind.CLASS: frozenset(
        {"struct_specifier", "union_specifier", "enum_specifier", "class_specifier"}
    ),
    NodeKind.METHOD: frozenset(),
    NodeKind.CALL: frozenset({"call_expression", "new_expression"}),
    NodeKind.IMPORT: frozenset({"preproc_include", "using_declaration"}),
    NodeKind.ASSIGNMENT: frozenset({"assignment_expression", "init_declarator"}),
    NodeKind.STRING: frozenset({"string_content", "raw_string_content", "preproc_arg"}),
    NodeKind.COMMENT: frozenset({"comment"}),
    NodeKind.IDENTIFIER: frozenset(
        {
            "identifier",
            "type_identifier",
            "field_identifier",
            "statement_identifier",
            "namespace_identifier",
        }
    ),
    NodeKind.PARAMETER: frozenset({"parameter_list", "parameter_declaration"}),
    NodeKind.FIELD: frozenset({"field_expression", "field_declaration"}),
    NodeKind.DECORATOR: frozenset(),
    NodeKind.BLOCK: frozenset({"compound_statement"}),
}

REGISTRY.register(
    TableSpec(
        Language.CPP,
        keywords=CPP_KEYWORDS,
        builtins=CPP_BUILTINS,
        kinds=_KINDS,
        rules=CPP_RULES,
        shapes=_SHAPES,
        comment_types=frozenset({"comment"}),
        extra_functions={"function_definition": definition_names},
    )
)
