"""Scoping and node kinds shared by the C and C++ specs (E07-05b).

Owning epic: E07.

C declarators nest (``char *q[100]``, ``int (*cb)(int)``), so the name of a declaration is found by
walking the ``declarator`` chain down to its identifier. ``function_definition`` declares its name
in the enclosing scope and opens a function scope that holds the parameters and the top-level
locals of the body; a prototype or function-pointer declarator opens a throwaway scope for its
parameter list. ``obj.field`` and ``ptr->field`` name external fields; a struct, union, enum or
class opens a class scope. C++ adds namespaces (which share the enclosing scope), templates (whose
parameters are declared where the template is), lambdas and qualified names.
"""

from typing import Final

from tree_sitter import Node

from codekavach.parsing.scopes import SymbolKind
from codekavach.parsing.specs.generic_scopes import (
    Binder,
    Names,
    Rules,
    all_children,
    by_field,
    first_child,
)

C_KEYWORDS: Final = frozenset(
    {
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
        "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
        "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
        "union", "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Noreturn",
        "NULL", "true", "false", "bool",
    }
)  # fmt: skip

CPP_KEYWORDS: Final = C_KEYWORDS | frozenset(
    {
        "alignas", "alignof", "and", "asm", "bitand", "bitor", "catch", "class", "compl",
        "concept", "consteval", "constexpr", "constinit", "const_cast", "co_await", "co_return",
        "co_yield", "decltype", "delete", "dynamic_cast", "explicit", "export", "friend", "mutable",
        "namespace", "new", "noexcept", "not", "nullptr", "operator", "or", "override", "final",
        "private", "protected", "public", "reinterpret_cast", "requires", "static_assert",
        "static_cast", "template", "this", "thread_local", "throw", "try", "typeid", "typename",
        "using", "virtual", "wchar_t", "xor", "char8_t", "char16_t", "char32_t",
    }
)  # fmt: skip

C_BUILTINS: Final = frozenset(
    {
        "printf", "fprintf", "sprintf", "snprintf", "vsprintf", "scanf", "sscanf", "fscanf",
        "gets", "fgets", "puts", "fputs", "getchar", "putchar", "malloc", "calloc", "realloc",
        "free", "memcpy", "memmove", "memset", "memcmp", "strcpy", "strncpy", "strcat", "strncat",
        "strcmp", "strncmp", "strlen", "strchr", "strrchr", "strstr", "strdup", "strtok", "atoi",
        "atol", "atof", "strtol", "strtoul", "abs", "rand", "srand", "time", "exit", "abort",
        "system", "popen", "pclose", "execl", "execv", "execve", "execlp", "execvp", "fork",
        "open", "close", "read", "write", "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
        "remove", "rename", "unlink", "access", "stat", "chmod", "chown", "getenv", "setenv",
        "socket", "bind", "listen", "accept", "connect", "send", "recv", "sendto", "recvfrom",
        "assert", "errno", "stdin", "stdout", "stderr", "size_t", "ssize_t", "FILE", "EOF",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
        "intptr_t", "uintptr_t", "ptrdiff_t", "main", "argc", "argv", "va_list", "va_start",
        "va_end", "va_arg", "mktemp", "tmpnam", "tempnam", "mkstemp", "crypt", "tolower",
        "toupper", "isalpha", "isdigit", "isspace", "qsort", "bsearch", "getpid", "sleep",
    }
)  # fmt: skip

CPP_BUILTINS: Final = C_BUILTINS | frozenset(
    {
        "std", "string", "vector", "map", "unordered_map", "set", "list", "deque", "array",
        "pair", "make_pair", "make_shared", "make_unique", "shared_ptr", "unique_ptr", "cout",
        "cin", "cerr", "endl", "ifstream", "ofstream", "fstream", "stringstream", "ostringstream",
        "istringstream", "move", "forward", "swap", "begin", "end", "size", "push_back", "emplace",
        "emplace_back", "find", "sort", "copy", "optional", "variant", "function", "thread",
        "mutex", "lock_guard", "exception", "runtime_error", "string_view", "to_string", "stoi",
        "getline", "c_str", "data", "length", "empty", "clear", "insert", "erase", "at", "reserve",
    }
)  # fmt: skip

_NAME_TYPES: Final = frozenset(
    {"identifier", "type_identifier", "field_identifier", "namespace_identifier"}
)
_CONTAINERS: Final = frozenset(
    {
        "pointer_declarator",
        "array_declarator",
        "function_declarator",
        "parenthesized_declarator",
        "reference_declarator",
        "init_declarator",
        "attributed_declarator",
    }
)


def declarator_name(node: Node | None) -> Node | None:
    """The identifier a declarator declares, found by walking down the ``declarator`` chain."""
    current = node
    while current is not None:
        if current.type in _NAME_TYPES:
            return current
        if current.type == "qualified_identifier":
            current = current.child_by_field_name("name")
            continue
        if current.type not in _CONTAINERS:
            return None
        nxt = current.child_by_field_name("declarator")
        if nxt is None:
            named = current.named_children
            nxt = named[0] if named else None
        current = nxt
    return None


def definition_names(node: Node) -> list[Node]:
    """The name of a ``function_definition`` as a one-element list (for the function walker)."""
    name = declarator_name(node.child_by_field_name("declarator"))
    return [] if name is None else [name]


def _top_is_function(declarator: Node | None) -> bool:
    """Whether the declarator is a function (``f(int)``) rather than a pointer to one."""
    current = declarator
    while current is not None and current.type in {"init_declarator", "attributed_declarator"}:
        current = current.child_by_field_name("declarator")
    return current is not None and current.type == "function_declarator"


def _declaration(node: Node, scope: int, binder: Binder) -> None:
    """A declaration, a field, a parameter or a typedef: each declarator declares one name."""
    in_class = binder.builder.kind_of(scope) == "class"
    for declarator in node.children_by_field_name("declarator"):
        name = declarator_name(declarator)
        if name is None:
            continue
        kind: SymbolKind
        if node.type == "type_definition":
            kind = "class"
        elif node.type in {"parameter_declaration", "optional_parameter_declaration"}:
            kind = "parameter"
        elif _top_is_function(declarator):
            kind = "method" if in_class else "function"
        elif node.type == "field_declaration":
            kind = "field"
        else:
            kind = binder.variable_kind(name, scope, "variable")
        binder.emit(name, scope, "define", kind)
    binder.push(node.named_children, scope)


def _function_definition(node: Node, scope: int, binder: Binder) -> None:
    declarator = node.child_by_field_name("declarator")
    name = declarator_name(declarator)
    function = binder.builder.open("function", scope)
    if name is not None:
        in_class = binder.builder.kind_of(scope) == "class"
        binder.emit(name, scope, "define", "method" if in_class else "function")
        binder.builder.extent(name.start_byte, node.start_byte, node.end_byte)
    frames: list[tuple[Node, int]] = []
    for child in node.named_children:
        if child.type == "compound_statement":
            frames.extend((inner, function) for inner in child.named_children)
        else:
            frames.append((child, function))
    binder.stack.extend(reversed(frames))


def _function_declarator(node: Node, scope: int, binder: Binder) -> None:
    """A prototype or a function-pointer declarator: its parameter list gets its own scope."""
    parent = node.parent
    owned = (
        parent is not None
        and parent.type == "function_definition"
        and parent.child_by_field_name("declarator") is not None
        and parent.child_by_field_name("declarator").id == node.id  # type: ignore[union-attr]
    )
    inner = scope if owned else binder.builder.open("function", scope)
    binder.push(node.named_children, inner)


def _template_parameter(node: Node, scope: int, binder: Binder) -> None:
    for name in first_child(frozenset({"type_identifier"}))(node):
        binder.emit(name, scope, "define", "class")
    binder.push(node.named_children, scope)


def _preproc_function(node: Node, scope: int, binder: Binder) -> None:
    name = node.child_by_field_name("name")
    function = binder.builder.open("function", scope)
    if name is not None:
        binder.emit(name, scope, "define", "function")
    binder.push([c for c in node.named_children if c.type == "preproc_params"], function)


_NAMES_ONLY: Final = frozenset({"identifier"})
_TYPE_NAME: Final = frozenset({"type_identifier"})


def _rules(*, cpp: bool) -> Rules:
    names = (
        _NAME_TYPES if cpp else frozenset({"identifier", "type_identifier", "field_identifier"})
    ) | {"statement_identifier"}
    types = {
        "struct_specifier": by_field(_TYPE_NAME, "name"),
        "union_specifier": by_field(_TYPE_NAME, "name"),
        "enum_specifier": by_field(_TYPE_NAME, "name"),
    }
    declarations: dict[str, tuple[Names, SymbolKind]] = {
        "enumerator": (by_field(_NAMES_ONLY, "name"), "constant"),
        "preproc_def": (by_field(_NAMES_ONLY, "name"), "constant"),
        "preproc_params": (all_children(_NAMES_ONLY), "parameter"),
    }
    members = {"field_expression": ("field",)}
    custom = {
        "declaration": _declaration,
        "field_declaration": _declaration,
        "parameter_declaration": _declaration,
        "optional_parameter_declaration": _declaration,
        "type_definition": _declaration,
        "function_definition": _function_definition,
        "function_declarator": _function_declarator,
        "preproc_function_def": _preproc_function,
    }
    blocks = frozenset(
        {
            "compound_statement",
            "for_statement",
            "switch_statement",
            "while_statement",
            "if_statement",
        }
    )
    paths: dict[str, tuple[Names, SymbolKind]] = {}
    lambdas: frozenset[str] = frozenset()
    if cpp:
        types["class_specifier"] = by_field(_TYPE_NAME, "name")
        declarations["namespace_definition"] = (
            by_field(frozenset({"namespace_identifier"}), "name"),
            "module",
        )
        declarations["alias_declaration"] = (by_field(_TYPE_NAME, "name"), "class")
        members["qualified_identifier"] = ("name",)
        custom["type_parameter_declaration"] = _template_parameter
        custom["optional_type_parameter_declaration"] = _template_parameter
        paths["field_initializer"] = (all_children(frozenset({"field_identifier"})), "field")
        blocks = blocks | {"for_range_loop", "catch_clause"}
        lambdas = frozenset({"lambda_expression"})
    return Rules(
        names=names,
        external_leaves={"statement_identifier": "variable"},
        types=types,
        lambdas=lambdas,
        blocks=blocks,
        declarations=declarations,
        members=members,
        paths=paths,
        custom=custom,
    )


C_RULES: Final = _rules(cpp=False)
CPP_RULES: Final = _rules(cpp=True)
