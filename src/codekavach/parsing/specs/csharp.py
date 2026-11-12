"""The C# ``LanguageSpec`` (E07-05b).

Owning epic: E07.

Registers at import time. C# names are ``identifier`` nodes (plus ``implicit_parameter`` for an
untyped lambda parameter, which is a leaf of its own). A namespace shares the module scope; a type
opens a class scope whose members every method sees; ``obj.Member`` and a named argument are
external occurrences. A ``using`` alias declares an import.
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
    all_children,
    by_field,
    first_child,
    leaves,
    no_names,
)

KEYWORDS: Final = frozenset(
    {
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else",
        "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for",
        "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock",
        "long", "namespace", "new", "null", "object", "operator", "out", "override", "params",
        "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short",
        "sizeof", "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true",
        "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "virtual",
        "void", "volatile", "while", "var", "async", "await", "get", "set", "init", "value",
        "record", "yield", "nameof", "dynamic", "partial", "where", "when", "with", "global",
        "required", "file", "scoped",
    }
)  # fmt: skip

BUILTINS: Final = frozenset(
    {
        "System", "String", "Int32", "Int64", "Boolean", "Object", "Console", "Exception", "Math",
        "Convert", "DateTime", "Guid", "List", "Dictionary", "IEnumerable", "Task", "Action",
        "Func", "Array", "StringBuilder", "Path", "File", "Directory", "Environment", "Process",
        "ProcessStartInfo", "HttpClient", "SqlConnection", "SqlCommand", "SqlDataReader",
        "MD5", "SHA1", "SHA256", "Aes", "DES", "Random", "BinaryFormatter", "XmlDocument",
        "Regex", "Linq", "Where", "Select", "ToList", "FirstOrDefault", "ExecuteReader",
        "ExecuteNonQuery", "ExecuteScalar", "WriteLine", "Write", "ReadLine", "Equals",
        "GetHashCode", "ToString", "Dispose", "IDisposable", "Main",
    }
)  # fmt: skip

_ID: Final = frozenset({"identifier"})
_TYPE_DECLARATIONS: Final = (
    "class_declaration",
    "struct_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "record_struct_declaration",
)


def _foreach(node: Node, scope: int, binder: Binder) -> None:
    """``foreach (var x in xs)``: the loop variable binds in the loop's own scope."""
    inner = binder.builder.open("block", scope)
    left = node.child_by_field_name("left")
    names = leaves(left, _ID) if left is not None and left.type == "identifier" else []
    for name in names:
        binder.emit(name, inner, "define", "variable")
    binder.push([c for c in node.named_children if c.id not in {n.id for n in names}], inner)


def _using(node: Node, scope: int, binder: Binder) -> None:
    """``using Alias = A.B;`` binds an import; ``using A.B;`` names an external path."""
    alias = node.child_by_field_name("name")
    for name in leaves(node, _ID):
        if alias is not None and name.id == alias.id:
            binder.emit(name, 0, "define", "import")
        else:
            binder.emit(name, scope, "external", "module")


_RULES: Final = Rules(
    names=_ID,
    types=dict.fromkeys(_TYPE_DECLARATIONS, by_field(_ID, "name")),
    functions={
        "method_declaration": by_field(_ID, "name"),
        "constructor_declaration": by_field(_ID, "name"),
        "destructor_declaration": by_field(_ID, "name"),
        "local_function_statement": by_field(_ID, "name"),
        "accessor_declaration": no_names,
        "operator_declaration": no_names,
    },
    constructors=frozenset({"constructor_declaration", "destructor_declaration"}),
    lambdas=frozenset({"lambda_expression", "anonymous_method_expression"}),
    blocks=frozenset(
        {
            "block",
            "for_statement",
            "using_statement",
            "catch_clause",
            "switch_section",
            "switch_expression_arm",
        }
    ),
    bodies=frozenset({"block", "arrow_expression_clause"}),
    declarations={
        "parameter": (by_field(_ID, "name"), "parameter"),
        "implicit_parameter": (lambda n: [n], "parameter"),
        "variable_declarator": (by_field(_ID, "name"), "variable"),
        "property_declaration": (by_field(_ID, "name"), "field"),
        "enum_member_declaration": (by_field(_ID, "name"), "constant"),
        "declaration_pattern": (by_field(_ID, "name"), "variable"),
        "catch_declaration": (by_field(_ID, "name"), "variable"),
        "type_parameter": (first_child(_ID), "class"),
    },
    members={
        "member_access_expression": ("name",),
        "member_binding_expression": ("name",),
        "qualified_name": ("name",),
    },
    paths={
        "namespace_declaration": (by_field(_ID, "name"), "module"),
        "file_scoped_namespace_declaration": (by_field(_ID, "name"), "module"),
        "name_colon": (all_children(_ID), "field"),
    },
    custom={"foreach_statement": _foreach, "using_directive": _using},
)

_SHAPES: Final = Shapes(
    literals=frozenset({"string_literal", "interpolated_string_expression", "raw_string_literal"}),
    content=frozenset({"string_literal_content", "string_content", "raw_string_content"}),
    binary="binary_expression",
    parenthesised="parenthesized_expression",
    call="invocation_expression",
    callee_field="function",
    arguments="argument_list",
    assignments=frozenset({"variable_declarator", "assignment_expression"}),
    wrappers=frozenset({"argument"}),
)

_KINDS: Final = {
    NodeKind.FUNCTION: frozenset(
        {"local_function_statement", "lambda_expression", "anonymous_method_expression"}
    ),
    NodeKind.CLASS: frozenset(_TYPE_DECLARATIONS),
    NodeKind.METHOD: frozenset({"method_declaration", "constructor_declaration"}),
    NodeKind.CALL: frozenset({"invocation_expression", "object_creation_expression"}),
    NodeKind.IMPORT: frozenset({"using_directive"}),
    NodeKind.ASSIGNMENT: frozenset({"assignment_expression", "variable_declarator"}),
    NodeKind.STRING: frozenset({"string_literal_content", "string_content", "raw_string_content"}),
    NodeKind.COMMENT: frozenset({"comment"}),
    NodeKind.IDENTIFIER: frozenset({"identifier", "implicit_parameter"}),
    NodeKind.PARAMETER: frozenset({"parameter_list", "parameter"}),
    NodeKind.FIELD: frozenset({"member_access_expression", "field_declaration"}),
    NodeKind.DECORATOR: frozenset({"attribute"}),
    NodeKind.BLOCK: frozenset({"block"}),
}

REGISTRY.register(
    TableSpec(
        Language.CSHARP,
        keywords=KEYWORDS,
        builtins=BUILTINS,
        kinds=_KINDS,
        rules=_RULES,
        shapes=_SHAPES,
        comment_types=frozenset({"comment"}),
    )
)
