"""The Java ``LanguageSpec`` (E07-05).

Owning epic: E07.

Registers at import time. Java's grammar uses ``identifier`` for variables, fields, methods and
packages, and ``type_identifier`` for type names, so ``node_kinds()`` maps ``NodeKind.IDENTIFIER``
to both. The scoping rules are in ``java_scopes``; the string-literal context is the shared
``c_style_literals`` walk, with the receiver and the method name of a call joined into the callee.
"""

from typing import Final, cast

from tree_sitter import Node as TSNode

from codekavach.core.models import Language
from codekavach.parsing.literals import LiteralContext
from codekavach.parsing.scopes import ScopeBuilder
from codekavach.parsing.spec import REGISTRY, NodeKind, NodeKindMap
from codekavach.parsing.specs.c_style_literals import Shapes, literal_context
from codekavach.parsing.specs.java_scopes import bind_java

KEYWORDS: Final = frozenset(
    {
        "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
        "const", "continue", "default", "do", "double", "else", "enum", "extends", "final",
        "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
        "interface", "long", "native", "new", "package", "private", "protected", "public",
        "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
        "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false",
        "null", "_",
        # Contextual keywords: reserved only in some positions, never a name a reviewer chose.
        "var", "yield", "record", "sealed", "non-sealed", "permits", "when", "module", "open",
        "opens", "requires", "exports", "provides", "uses", "with", "to", "transitive",
    }
)  # fmt: skip

# The java.lang names every compilation unit sees without an import, plus the annotations the
# language itself defines. They are the language's own vocabulary, not a project's.
BUILTINS: Final = frozenset(
    {
        "String", "Object", "Integer", "Long", "Double", "Float", "Boolean", "Byte", "Short",
        "Character", "Number", "Math", "StrictMath", "System", "Class", "ClassLoader", "Enum",
        "Record", "Void", "Runnable", "Thread", "ThreadLocal", "Runtime", "Process",
        "ProcessBuilder", "StringBuilder", "StringBuffer", "CharSequence", "Iterable",
        "Comparable", "AutoCloseable", "Cloneable", "Throwable", "Exception", "RuntimeException",
        "Error", "AssertionError", "IllegalArgumentException", "IllegalStateException",
        "NullPointerException", "IndexOutOfBoundsException", "ArithmeticException",
        "ClassCastException", "UnsupportedOperationException", "InterruptedException",
        "CloneNotSupportedException", "SecurityException", "StackOverflowError",
        "OutOfMemoryError", "Override", "Deprecated", "SuppressWarnings", "FunctionalInterface",
        "SafeVarargs",
    }
)  # fmt: skip

_ENCLOSING: Final = frozenset(
    {
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "annotation_type_declaration",
        "method_declaration",
        "constructor_declaration",
        "compact_constructor_declaration",
    }
)

_SHAPES: Final = Shapes(
    literals=frozenset({"string_literal"}),
    content=frozenset({"string_fragment", "multiline_string_fragment"}),
    binary="binary_expression",
    parenthesised="parenthesized_expression",
    call="method_invocation",
    callee_field="name",
    arguments="argument_list",
    assignments=frozenset({"variable_declarator", "assignment_expression"}),
)


class JavaSpec:
    """The ``LanguageSpec`` for Java."""

    language = Language.JAVA
    grammar_version = "tree-sitter-language-pack"
    keywords = KEYWORDS
    builtins = BUILTINS
    # A method body sees the fields of its class by their bare names; the class scope encloses it.
    class_body_sees_members = True
    class_scopes_visible = True

    def bind_scopes(self, root: object, builder: ScopeBuilder) -> None:
        """Feed ``builder`` the scopes and identifier occurrences of the tree rooted at ``root``."""
        bind_java(cast(TSNode, root), builder)

    def node_kinds(self) -> NodeKindMap:
        """Map each ``NodeKind`` to the Java grammar's node-type names that mean it."""
        return {
            NodeKind.FUNCTION: frozenset({"lambda_expression"}),
            NodeKind.CLASS: frozenset(
                {
                    "class_declaration",
                    "interface_declaration",
                    "enum_declaration",
                    "record_declaration",
                    "annotation_type_declaration",
                }
            ),
            NodeKind.METHOD: frozenset(
                {"method_declaration", "constructor_declaration", "compact_constructor_declaration"}
            ),
            NodeKind.CALL: frozenset({"method_invocation", "object_creation_expression"}),
            NodeKind.IMPORT: frozenset({"import_declaration"}),
            NodeKind.ASSIGNMENT: frozenset({"assignment_expression", "variable_declarator"}),
            NodeKind.STRING: frozenset({"string_fragment", "multiline_string_fragment"}),
            NodeKind.COMMENT: frozenset({"line_comment", "block_comment"}),
            NodeKind.IDENTIFIER: frozenset({"identifier", "type_identifier"}),
            NodeKind.PARAMETER: frozenset(
                {
                    "formal_parameters",
                    "formal_parameter",
                    "spread_parameter",
                    "catch_formal_parameter",
                }
            ),
            NodeKind.FIELD: frozenset({"field_access", "field_declaration"}),
            NodeKind.DECORATOR: frozenset({"annotation", "marker_annotation"}),
            NodeKind.BLOCK: frozenset({"block", "constructor_body"}),
        }

    def enclosing_symbol(self, node: object, source: str) -> str | None:
        """The ``Class.method`` name of the declaration ``node`` is nested in, if any."""
        return enclosing_symbol(cast(TSNode, node))

    def literal_context(self, node: object) -> LiteralContext:
        """The classifier context for the string-content node ``node``."""
        return literal_context(cast(TSNode, node), _SHAPES)


def enclosing_symbol(node: TSNode) -> str | None:
    """Walk up from ``node`` through every enclosing type and method, joining the names by dots."""
    if node.type in ("line_comment", "block_comment"):
        return None
    names: list[str] = []
    current = node.parent
    while current is not None:
        if current.type in _ENCLOSING:
            name = current.child_by_field_name("name")
            if name is not None and name.text is not None:
                names.append(name.text.decode("utf-8", errors="replace"))
        current = current.parent
    return ".".join(reversed(names)) if names else None


REGISTRY.register(JavaSpec())
