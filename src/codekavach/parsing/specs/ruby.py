"""The Ruby ``LanguageSpec`` (E07-05b).

Owning epic: E07.

Registers at import time. Ruby has no declarations: a local comes into being by assignment, so an
assignment to a plain name declares it in the current function scope (a ``def``, a block, a
lambda). ``@x``, ``@@x`` and ``$x`` carry their sigil in the node text, as do symbols (``:x``);
the renamer keeps the sigil. A call with a receiver names an external method.
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
    leaves,
    no_names,
)

KEYWORDS: Final = frozenset(
    {
        "alias", "and", "begin", "break", "case", "class", "def", "defined?", "do", "else",
        "elsif", "end", "ensure", "false", "for", "if", "in", "module", "next", "nil", "not", "or",
        "redo", "rescue", "retry", "return", "self", "super", "then", "true", "undef", "unless",
        "until", "when", "while", "yield", "__method__", "__FILE__", "__LINE__",
    }
)  # fmt: skip

BUILTINS: Final = frozenset(
    {
        "puts", "print", "p", "pp", "require", "require_relative", "load", "raise", "attr_reader",
        "attr_writer", "attr_accessor", "include", "extend", "prepend", "private", "protected",
        "public", "module_function", "lambda", "proc", "loop", "format", "sprintf", "printf",
        "gets", "sleep", "rand", "srand", "exit", "abort", "at_exit", "catch", "throw", "binding",
        "eval", "instance_eval", "class_eval", "send", "public_send", "define_method",
        "method_missing", "respond_to?", "initialize", "new", "to_s", "to_i", "to_a", "to_h",
        "each", "map", "select", "reject", "reduce", "inject", "first", "last", "length", "size",
        "nil?", "empty?", "freeze", "dup", "clone", "tap", "then", "Integer", "Float", "String",
        "Array", "Hash", "Struct", "Object", "Module", "Class", "Kernel", "Comparable",
        "Enumerable", "File", "Dir", "IO", "Time", "Date", "JSON", "YAML", "Marshal", "ENV",
        "ARGV", "Process", "Open3", "Net", "HTTP", "URI", "Digest", "OpenSSL", "SecureRandom",
        "Base64", "ERB", "Regexp", "Symbol", "Exception", "StandardError", "RuntimeError",
        "ArgumentError", "NotImplementedError", "system", "exec", "spawn", "popen", "open",
    }
)  # fmt: skip

_VARIABLES: Final = frozenset(
    {"identifier", "constant", "instance_variable", "class_variable", "global_variable"}
)
_NAMES: Final = _VARIABLES | {"simple_symbol", "hash_key_symbol"}
_IDENT: Final = frozenset({"identifier"})


def _assigned(node: Node) -> list[Node]:
    left = node.child_by_field_name("left")
    if left is None:
        return []
    if left.type in _VARIABLES:
        return [left]
    if left.type in {"left_assignment_list", "destructured_left_assignment"}:
        return leaves(left, _VARIABLES)
    return []


def _call(node: Node, scope: int, binder: Binder) -> None:
    """``recv.method(...)``: with a receiver the method is external; without one it is a use."""
    receiver = node.child_by_field_name("receiver")
    method = node.child_by_field_name("method")
    claimed: list[Node] = []
    if receiver is not None and method is not None and method.type in _NAMES:
        binder.emit(method, scope, "external", "method")
        claimed.append(method)
    binder.push([c for c in node.named_children if c not in claimed], scope)


_RULES: Final = Rules(
    names=_NAMES,
    types={
        "class": by_field(frozenset({"constant"}), "name"),
        "module": by_field(frozenset({"constant"}), "name"),
        "singleton_class": no_names,
    },
    functions={
        "method": by_field(_IDENT, "name"),
        "singleton_method": by_field(_IDENT, "name"),
    },
    lambdas=frozenset({"lambda", "block", "do_block"}),
    declarations={
        "method_parameters": (all_children(_IDENT), "parameter"),
        "block_parameters": (all_children(_IDENT), "parameter"),
        "lambda_parameters": (all_children(_IDENT), "parameter"),
        "optional_parameter": (by_field(_IDENT, "name"), "parameter"),
        "keyword_parameter": (by_field(_IDENT, "name"), "parameter"),
        "splat_parameter": (by_field(_IDENT, "name"), "parameter"),
        "hash_splat_parameter": (by_field(_IDENT, "name"), "parameter"),
        "block_parameter": (by_field(_IDENT, "name"), "parameter"),
        "exception_variable": (all_children(_IDENT), "variable"),
    },
    members={"scope_resolution": ("name",), "pair": ("key",)},
    assignments={"assignment": _assigned, "operator_assignment": _assigned},
    custom={"call": _call},
)

_SHAPES: Final = Shapes(
    literals=frozenset({"string"}),
    content=frozenset({"string_content"}),
    binary="binary",
    parenthesised="parenthesized_statements",
    call="call",
    callee_field="method",
    arguments="argument_list",
    assignments=frozenset({"assignment"}),
)

_KINDS: Final = {
    NodeKind.FUNCTION: frozenset({"lambda", "block", "do_block"}),
    NodeKind.CLASS: frozenset({"class", "module", "singleton_class"}),
    NodeKind.METHOD: frozenset({"method", "singleton_method"}),
    NodeKind.CALL: frozenset({"call"}),
    NodeKind.IMPORT: frozenset(),
    NodeKind.ASSIGNMENT: frozenset({"assignment", "operator_assignment"}),
    NodeKind.STRING: frozenset({"string_content", "heredoc_content"}),
    NodeKind.COMMENT: frozenset({"comment"}),
    NodeKind.IDENTIFIER: _NAMES,
    NodeKind.PARAMETER: frozenset({"method_parameters", "block_parameters", "lambda_parameters"}),
    NodeKind.FIELD: frozenset({"instance_variable", "scope_resolution"}),
    NodeKind.DECORATOR: frozenset(),
    NodeKind.BLOCK: frozenset({"body_statement", "block_body"}),
}

REGISTRY.register(
    TableSpec(
        Language.RUBY,
        keywords=KEYWORDS,
        builtins=BUILTINS,
        kinds=_KINDS,
        rules=_RULES,
        shapes=_SHAPES,
        comment_types=frozenset({"comment"}),
        members_visible=False,
    )
)
