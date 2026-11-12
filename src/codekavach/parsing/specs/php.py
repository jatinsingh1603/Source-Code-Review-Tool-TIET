"""The PHP ``LanguageSpec`` (E07-05b).

Owning epic: E07.

Registers at import time. Every PHP name is a ``name`` node: a variable is a ``variable_name``
holding a ``name`` (the ``$`` stays outside the node, so a rename keeps it), and a property, a
method and a class are ``name`` nodes too. ``$this->x`` and ``Type::x`` members are external
occurrences; a plain assignment to a variable declares it in the current function scope.
"""

from typing import Final

from tree_sitter import Node

from codekavach.core.models import Language
from codekavach.parsing.spec import REGISTRY, NodeKind
from codekavach.parsing.specs.c_style_literals import Shapes
from codekavach.parsing.specs.generic import TableSpec
from codekavach.parsing.specs.generic_scopes import (
    Binder,
    Rules,
    by_field,
    first_child,
    leaves,
)

KEYWORDS: Final = frozenset(
    {
        "abstract", "and", "array", "as", "break", "callable", "case", "catch", "class", "clone",
        "const", "continue", "declare", "default", "do", "echo", "else", "elseif", "empty",
        "enddeclare", "endfor", "endforeach", "endif", "endswitch", "endwhile", "enum", "eval",
        "exit", "die", "extends", "final", "finally", "fn", "for", "foreach", "function", "global",
        "goto", "if", "implements", "include", "include_once", "instanceof", "insteadof",
        "interface", "isset", "list", "match", "namespace", "new", "or", "print", "private",
        "protected", "public", "readonly", "require", "require_once", "return", "static", "switch",
        "throw", "trait", "try", "unset", "use", "var", "while", "xor", "yield", "this", "self",
        "parent", "true", "false", "null", "int", "float", "string", "bool", "mixed", "void",
        "never", "iterable", "object",
    }
)  # fmt: skip

BUILTINS: Final = frozenset(
    {
        "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER", "_SESSION", "_ENV", "GLOBALS",
        "strlen", "count", "in_array", "array_map", "array_filter", "array_keys", "array_merge",
        "implode", "explode", "sprintf", "printf", "intval", "json_encode", "json_decode",
        "htmlspecialchars", "password_hash", "password_verify", "md5", "sha1", "hash", "trim",
        "str_replace", "substr", "strpos", "preg_match", "preg_replace", "file_get_contents",
        "file_put_contents", "fopen", "unlink", "header", "exec", "system", "shell_exec",
        "passthru", "unserialize", "serialize", "mysqli_query", "move_uploaded_file", "rand",
        "mt_rand", "random_bytes", "openssl_encrypt", "openssl_decrypt", "curl_init", "curl_exec",
        "Exception", "PDO", "DateTime", "ArrayObject", "Closure",
    }
)  # fmt: skip

_NAME: Final = frozenset({"name"})


def _left_variable(node: Node) -> list[Node]:
    left = node.child_by_field_name("left")
    if left is not None and left.type == "variable_name":
        return leaves(left, _NAME)
    return []


def _foreach(node: Node, scope: int, binder: Binder) -> None:
    """``foreach ($rows as $k => $v)``: the loop variables bind in the loop's own scope."""
    inner = binder.builder.open("block", scope)
    named = node.named_children
    body = node.child_by_field_name("body")
    for index, child in enumerate(named):
        if body is not None and child.id == body.id:
            binder.push([child], inner)
        elif index == 0:
            binder.push([child], scope)
        else:
            for name in leaves(child, _NAME):
                binder.emit(name, inner, "define", "variable")
            binder.push([child], inner)


def _use_clause(node: Node, scope: int, binder: Binder) -> None:
    r"""``use A\B as C``: the path is external, an alias binds an import in the module scope."""
    alias = node.child_by_field_name("alias")
    for name in leaves(node, _NAME):
        if alias is not None and name.id == alias.id:
            binder.emit(name, 0, "define", "import")
        else:
            binder.emit(name, scope, "external", "module")


def _class_constant(node: Node, scope: int, binder: Binder) -> None:
    """``Repo::MAX``: the first name is the class, the last is its member."""
    named = [c for c in node.named_children if c.type == "name"]
    for index, name in enumerate(named):
        if index == len(named) - 1 and index > 0:
            binder.emit(name, scope, "external", "constant")
        else:
            binder.emit(name, scope, "reference", "class")
    binder.push([c for c in node.named_children if c.type != "name"], scope)


_RULES: Final = Rules(
    names=_NAME,
    types={
        "class_declaration": by_field(_NAME, "name"),
        "interface_declaration": by_field(_NAME, "name"),
        "trait_declaration": by_field(_NAME, "name"),
        "enum_declaration": by_field(_NAME, "name"),
    },
    functions={
        "function_definition": by_field(_NAME, "name"),
        "method_declaration": by_field(_NAME, "name"),
    },
    lambdas=frozenset({"anonymous_function", "arrow_function"}),
    blocks=frozenset({"catch_clause", "for_statement", "while_statement"}),
    declarations={
        "simple_parameter": (by_field(_NAME, "name"), "parameter"),
        "variadic_parameter": (by_field(_NAME, "name"), "parameter"),
        "property_promotion_parameter": (by_field(_NAME, "name"), "field"),
        "property_element": (by_field(_NAME, "name"), "variable"),
        "const_element": (first_child(_NAME), "constant"),
        "enum_case": (by_field(_NAME, "name"), "constant"),
        "static_variable_declaration": (by_field(_NAME, "name"), "variable"),
    },
    members={
        "member_access_expression": ("name",),
        "member_call_expression": ("name",),
        "nullsafe_member_access_expression": ("name",),
        "nullsafe_member_call_expression": ("name",),
        "scoped_call_expression": ("name",),
        "argument": ("name",),
    },
    paths={"namespace_definition": (by_field(_NAME, "name"), "module")},
    assignments={
        "assignment_expression": _left_variable,
        "augmented_assignment_expression": _left_variable,
    },
    custom={
        "foreach_statement": _foreach,
        "namespace_use_clause": _use_clause,
        "class_constant_access_expression": _class_constant,
    },
    constructors=frozenset(),
)

_SHAPES: Final = Shapes(
    literals=frozenset({"string", "encapsed_string"}),
    content=frozenset({"string_content"}),
    binary="binary_expression",
    parenthesised="parenthesized_expression",
    call="function_call_expression",
    callee_field="function",
    arguments="arguments",
    assignments=frozenset({"assignment_expression"}),
    plus=".",
    wrappers=frozenset({"argument"}),
    extra_calls=frozenset({"member_call_expression", "scoped_call_expression"}),
)

_KINDS: Final = {
    NodeKind.FUNCTION: frozenset(
        {"function_definition", "anonymous_function", "arrow_function", "method_declaration"}
    ),
    NodeKind.CLASS: frozenset(
        {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}
    ),
    NodeKind.METHOD: frozenset({"method_declaration"}),
    NodeKind.CALL: frozenset(
        {
            "function_call_expression",
            "member_call_expression",
            "scoped_call_expression",
            "object_creation_expression",
        }
    ),
    NodeKind.IMPORT: frozenset({"namespace_use_declaration"}),
    NodeKind.ASSIGNMENT: frozenset({"assignment_expression", "augmented_assignment_expression"}),
    NodeKind.STRING: frozenset({"string_content"}),
    NodeKind.COMMENT: frozenset({"comment"}),
    NodeKind.IDENTIFIER: _NAME,
    NodeKind.PARAMETER: frozenset({"formal_parameters", "simple_parameter", "variadic_parameter"}),
    NodeKind.FIELD: frozenset({"member_access_expression", "property_declaration"}),
    NodeKind.DECORATOR: frozenset({"attribute"}),
    NodeKind.BLOCK: frozenset({"compound_statement"}),
}

REGISTRY.register(
    TableSpec(
        Language.PHP,
        keywords=KEYWORDS,
        builtins=BUILTINS,
        kinds=_KINDS,
        rules=_RULES,
        shapes=_SHAPES,
        comment_types=frozenset({"comment"}),
        members_visible=False,
    )
)
