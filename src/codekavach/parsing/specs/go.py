"""The Go ``LanguageSpec`` (E07-05).

Owning epic: E07.

Registers at import time. Go's grammar has five name node types: ``identifier`` for variables and
functions, ``type_identifier`` for types, ``field_identifier`` for struct fields, methods and
selector fields, ``package_identifier`` for the package clause and an import alias, and
``label_name`` for a label. The scoping rules are in ``go_scopes``.
"""

from typing import Final, cast

from tree_sitter import Node as TSNode

from codekavach.core.models import Language
from codekavach.parsing.literals import LiteralContext
from codekavach.parsing.scopes import ScopeBuilder
from codekavach.parsing.spec import REGISTRY, NodeKind, NodeKindMap
from codekavach.parsing.specs.c_style_literals import Shapes, literal_context
from codekavach.parsing.specs.go_scopes import bind_go

KEYWORDS: Final = frozenset(
    {
        "break", "default", "func", "interface", "select", "case", "defer", "go", "map", "struct",
        "chan", "else", "goto", "package", "switch", "const", "fallthrough", "if", "range", "type",
        "continue", "for", "import", "return", "var", "_",
    }
)  # fmt: skip

# The predeclared identifiers of the universe scope: types, constants and functions.
BUILTINS: Final = frozenset(
    {
        "any", "bool", "byte", "comparable", "complex64", "complex128", "error", "float32",
        "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8",
        "uint16", "uint32", "uint64", "uintptr", "true", "false", "iota", "nil", "append", "cap",
        "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max", "min", "new",
        "panic", "print", "println", "real", "recover",
    }
)  # fmt: skip

_SHAPES: Final = Shapes(
    literals=frozenset({"interpreted_string_literal", "raw_string_literal"}),
    content=frozenset({"interpreted_string_literal_content", "raw_string_literal_content"}),
    binary="binary_expression",
    parenthesised="parenthesized_expression",
    call="call_expression",
    callee_field="function",
    arguments="argument_list",
    assignments=frozenset(
        {"short_var_declaration", "var_spec", "const_spec", "assignment_statement"}
    ),
)


class GoSpec:
    """The ``LanguageSpec`` for Go."""

    language = Language.GO
    grammar_version = "tree-sitter-language-pack"
    keywords = KEYWORDS
    builtins = BUILTINS
    # Go has no class bodies: struct fields and methods are reached through a selector only.
    class_body_sees_members = False
    class_scopes_visible = False

    def bind_scopes(self, root: object, builder: ScopeBuilder) -> None:
        """Feed ``builder`` the scopes and identifier occurrences of the tree rooted at ``root``."""
        bind_go(cast(TSNode, root), builder)

    def node_kinds(self) -> NodeKindMap:
        """Map each ``NodeKind`` to the Go grammar's node-type names that mean it."""
        return {
            NodeKind.FUNCTION: frozenset({"function_declaration", "func_literal"}),
            NodeKind.CLASS: frozenset({"type_spec", "type_alias"}),
            NodeKind.METHOD: frozenset({"method_declaration"}),
            NodeKind.CALL: frozenset({"call_expression"}),
            NodeKind.IMPORT: frozenset({"import_declaration", "import_spec"}),
            NodeKind.ASSIGNMENT: frozenset(
                {"assignment_statement", "short_var_declaration", "var_spec", "const_spec"}
            ),
            NodeKind.STRING: frozenset(
                {"interpreted_string_literal_content", "raw_string_literal_content"}
            ),
            NodeKind.COMMENT: frozenset({"comment"}),
            NodeKind.IDENTIFIER: frozenset(
                {
                    "identifier",
                    "type_identifier",
                    "field_identifier",
                    "package_identifier",
                    "label_name",
                }
            ),
            NodeKind.PARAMETER: frozenset(
                {"parameter_list", "parameter_declaration", "variadic_parameter_declaration"}
            ),
            NodeKind.FIELD: frozenset({"selector_expression", "field_declaration"}),
            NodeKind.DECORATOR: frozenset(),
            NodeKind.BLOCK: frozenset({"block"}),
        }

    def enclosing_symbol(self, node: object, source: str) -> str | None:
        """``Func`` or ``(*Receiver).Method``: the declaration ``node`` is nested in, if any."""
        return enclosing_symbol(cast(TSNode, node))

    def literal_context(self, node: object) -> LiteralContext:
        """The classifier context for the string-content node ``node``."""
        return literal_context(cast(TSNode, node), _SHAPES)


def _text(node: TSNode | None) -> str | None:
    if node is None or node.text is None:
        return None
    return node.text.decode("utf-8", errors="replace")


def _receiver_type(method: TSNode) -> str | None:
    """The receiver's type as written (``*Engine``, ``Engine[T]``), without its name."""
    receiver = method.child_by_field_name("receiver")
    if receiver is None:
        return None
    for parameter in receiver.named_children:
        written = _text(parameter.child_by_field_name("type"))
        if written is not None:
            return written
    return None


def enclosing_symbol(node: TSNode) -> str | None:
    """The outermost named function or method around ``node``; a literal is not named."""
    if node.type == "comment":
        return None
    current = node.parent
    while current is not None:
        if current.type == "method_declaration":
            name = _text(current.child_by_field_name("name"))
            receiver = _receiver_type(current)
            if name is not None:
                return f"({receiver}).{name}" if receiver else name
        if current.type == "function_declaration":
            return _text(current.child_by_field_name("name"))
        current = current.parent
    return None


REGISTRY.register(GoSpec())
