"""Python scoping rules for the symbol table (E07-03).

Owning epic: E07.

``bind_python`` walks the tree once with an explicit stack and feeds a ``ScopeBuilder``; nothing
is resolved here (see ``codekavach.parsing.scopes``). Every ``identifier`` node reaches the
builder exactly once: the handlers below classify the ones whose role is not "a use of a name",
and any other identifier falls through to a plain reference.

The rules, in the terms of the language reference:

* module, function and class scopes; a class body does not enclose the bodies of its methods;
* a lambda and every comprehension or generator expression is its own function scope, and the
  first iterable of a comprehension is evaluated in the enclosing scope;
* parameters bind in the function scope, their defaults and annotations are evaluated in the
  enclosing scope;
* assignment, augmented assignment, ``for`` targets, ``with ... as``, ``except ... as``,
  imports, ``def`` and ``class`` bind in the current scope; a walrus target binds in the
  nearest enclosing function (never a comprehension);
* ``global`` and ``nonlocal`` redirect a name for the whole function body;
* attribute names and keyword-argument names are not variables: they are external occurrences
  (``scope_id == -1``) of kind ``field`` and ``parameter``.

``match`` statements are handled for the common patterns (capture, class, keyword, sequence,
mapping, ``as``, union); an unusual pattern degrades to a reference, never to a wrong binding.
"""

from collections.abc import Callable
from typing import Final, cast

from tree_sitter import Node

from codekavach.parsing.scopes import MODULE_SCOPE, Role, ScopeBuilder, SymbolKind

REF: Final = 0
BIND: Final = 1
CASE: Final = 2

Frame = tuple[Node, int, int, str]
Handler = Callable[[Node, int, int, str, ScopeBuilder, list[Frame]], None]

# Nodes whose children are themselves binding targets when the node is one.
_CONTAINERS: Final = frozenset(
    {
        "pattern_list",
        "tuple_pattern",
        "list_pattern",
        "list_splat_pattern",
        "dictionary_splat_pattern",
        "tuple",
        "list",
        "expression_list",
        "parenthesized_expression",
        "as_pattern_target",
    }
)
_COMPREHENSIONS: Final = frozenset(
    {"list_comprehension", "set_comprehension", "dictionary_comprehension", "generator_expression"}
)


def _text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")


def _fielded(node: Node) -> list[tuple[Node, str | None]]:
    """The named children of ``node`` with the field name each one has, if any."""
    return [
        (child, node.field_name_for_child(index))
        for index, child in enumerate(node.children)
        if child.is_named
    ]


def _emit(
    builder: ScopeBuilder,
    node: Node,
    scope: int,
    role: Role,
    kind: SymbolKind = "variable",
) -> None:
    builder.occur(node.start_byte, node.end_byte, _text(node), scope, role, kind)


def _auto_kind(builder: ScopeBuilder, scope: int, name: str) -> SymbolKind:
    """The kind of a plain assignment target: field in a class body, constant if SCREAMING."""
    scope_kind = builder.kind_of(scope)
    if scope_kind == "class":
        return "field"
    if scope_kind == "module" and name.isupper():
        return "constant"
    return "variable"


def _identifiers_in(node: Node) -> list[Node]:
    found: list[Node] = []
    pending = [node]
    while pending:
        current = pending.pop()
        if current.type == "identifier":
            found.append(current)
        pending.extend(current.named_children)
    return found


def _push_children(node: Node, scope: int, mode: int, kind: str, stack: list[Frame]) -> None:
    child_mode = mode if mode == CASE or node.type in _CONTAINERS else REF
    stack.extend((child, scope, child_mode, kind) for child in reversed(node.named_children))


def _identifier(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    if mode == REF:
        _emit(builder, node, scope, "reference")
        return
    name = _text(node)
    resolved = _auto_kind(builder, scope, name) if kind == "auto" else cast(SymbolKind, kind)
    builder.occur(node.start_byte, node.end_byte, name, scope, "define", resolved)


def _push_parameters(parameters: Node, outer: int, inner: int, stack: list[Frame]) -> None:
    for child in parameters.named_children:
        if child.type in ("default_parameter", "typed_default_parameter"):
            for sub, field in _fielded(child):
                if field == "name":
                    stack.append((sub, inner, BIND, "parameter"))
                else:
                    stack.append((sub, outer, REF, "auto"))
        elif child.type == "typed_parameter":
            for sub, field in _fielded(child):
                if field == "type":
                    stack.append((sub, outer, REF, "auto"))
                else:
                    stack.append((sub, inner, BIND, "parameter"))
        else:
            stack.append((child, inner, BIND, "parameter"))


def _function(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    inner = builder.open("function", scope)
    name = node.child_by_field_name("name")
    if name is not None:
        symbol_kind: SymbolKind = "method" if builder.kind_of(scope) == "class" else "function"
        _emit(builder, name, scope, "define", symbol_kind)
        parent = node.parent
        full = parent if parent is not None and parent.type == "decorated_definition" else node
        builder.extent(name.start_byte, full.start_byte, full.end_byte)
    for child, field in _fielded(node):
        if field == "name":
            continue
        if field == "parameters":
            _push_parameters(child, scope, inner, stack)
        elif field == "body":
            stack.append((child, inner, REF, "auto"))
        else:  # return type, type parameters, comments
            stack.append((child, scope, REF, "auto"))


def _lambda(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    inner = builder.open("function", scope)
    for child, field in _fielded(node):
        if field == "parameters":
            _push_parameters(child, scope, inner, stack)
        else:
            stack.append((child, inner, REF, "auto"))


def _class(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    inner = builder.open("class", scope)
    name = node.child_by_field_name("name")
    if name is not None:
        _emit(builder, name, scope, "define", "class")
        parent = node.parent
        full = parent if parent is not None and parent.type == "decorated_definition" else node
        builder.extent(name.start_byte, full.start_byte, full.end_byte)
    for child, field in _fielded(node):
        if field == "name":
            continue
        stack.append((child, inner if field == "body" else scope, REF, "auto"))


def _comprehension(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    inner = builder.open("function", scope, comprehension=True)
    first_clause = True
    for child, _ in _fielded(node):
        if child.type != "for_in_clause":
            stack.append((child, inner, REF, "auto"))
            continue
        for sub, field in _fielded(child):
            if field == "left":
                stack.append((sub, inner, BIND, "variable"))
            elif field == "right":
                stack.append((sub, scope if first_clause else inner, REF, "auto"))
            else:
                stack.append((sub, inner, REF, "auto"))
        first_clause = False


def _walrus(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    target = builder.enclosing_function(scope)
    for child, field in _fielded(node):
        if field == "name":
            name = _text(child)
            builder.occur(
                child.start_byte,
                child.end_byte,
                name,
                target,
                "define",
                _auto_kind(builder, target, name),
            )
        else:
            stack.append((child, scope, REF, "auto"))


def _assignment(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, field in _fielded(node):
        if field == "left":
            stack.append((child, scope, BIND, "auto"))
        else:
            stack.append((child, scope, REF, "auto"))


def _for_statement(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    _assignment(node, scope, mode, kind, builder, stack)


def _as_pattern(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, field in _fielded(node):
        if field == "alias":
            stack.append((child, scope, BIND, "variable"))
        else:
            stack.append((child, scope, CASE if mode == CASE else REF, "auto"))


def _scope_statement(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    """``global`` and ``nonlocal``: redirect the names, then record each as a use."""
    declare = (
        builder.declare_global if node.type == "global_statement" else builder.declare_nonlocal
    )
    for child in node.named_children:
        if child.type == "identifier":
            declare(scope, _text(child))
            _emit(builder, child, scope, "reference")


def _attribute(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, field in _fielded(node):
        if field == "attribute":
            _emit(builder, child, scope, "external", "field")
        else:
            stack.append((child, scope, REF, "auto"))


def _keyword_argument(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, field in _fielded(node):
        if field == "name":
            _emit(builder, child, scope, "external", "parameter")
        else:
            stack.append((child, scope, REF, "auto"))


def _import_dotted(name: Node, scope: int, builder: ScopeBuilder) -> None:
    """``import a.b.c`` binds ``a``; ``b`` and ``c`` are members of the module."""
    for index, identifier in enumerate(_identifiers_in(name)[::-1]):
        if index == 0:
            _emit(builder, identifier, scope, "define", "import")
        else:
            _emit(builder, identifier, scope, "external", "module")


def _import(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, field in _fielded(node):
        if field != "name":
            continue
        if child.type == "aliased_import":
            for sub, sub_field in _fielded(child):
                if sub_field == "alias":
                    _emit(builder, sub, scope, "define", "import")
                else:
                    for identifier in _identifiers_in(sub):
                        _emit(builder, identifier, scope, "external", "module")
        else:
            _import_dotted(child, scope, builder)


def _import_from(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, field in _fielded(node):
        if field == "module_name":
            for identifier in _identifiers_in(child):
                _emit(builder, identifier, scope, "external", "module")
        elif field == "name" and child.type == "aliased_import":
            for sub, sub_field in _fielded(child):
                if sub_field == "alias":
                    _emit(builder, sub, scope, "define", "import")
                else:
                    for identifier in _identifiers_in(sub):
                        _emit(builder, identifier, scope, "external", "import")
        elif field == "name":
            for identifier in _identifiers_in(child):
                _emit(builder, identifier, scope, "define", "import")


def _case_clause(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, _ in _fielded(node):
        stack.append((child, scope, CASE if child.type == "case_pattern" else REF, "auto"))


def _case_dotted_name(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    """In a pattern a bare name captures; a dotted name is a value pattern (a use)."""
    identifiers = _identifiers_in(node)[::-1]
    if len(identifiers) == 1:
        _emit(builder, identifiers[0], scope, "define", "variable")
        return
    for index, identifier in enumerate(identifiers):
        if index == 0:
            _emit(builder, identifier, scope, "reference")
        else:
            _emit(builder, identifier, scope, "external", "field")


def _class_pattern(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for index, (child, _) in enumerate(_fielded(node)):
        if index == 0 and child.type == "dotted_name":
            for position, identifier in enumerate(_identifiers_in(child)[::-1]):
                if position == 0:
                    _emit(builder, identifier, scope, "reference")
                else:
                    _emit(builder, identifier, scope, "external", "field")
        else:
            stack.append((child, scope, CASE, "auto"))


def _keyword_pattern(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for index, (child, _) in enumerate(_fielded(node)):
        if index == 0 and child.type == "identifier":
            _emit(builder, child, scope, "external", "parameter")
        else:
            stack.append((child, scope, CASE, "auto"))


def _dict_pattern(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    for child, field in _fielded(node):
        stack.append((child, scope, REF if field == "key" else CASE, "auto"))


def _dotted_name(
    node: Node, scope: int, mode: int, kind: str, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    if mode == CASE:
        _case_dotted_name(node, scope, mode, kind, builder, stack)
    else:
        _push_children(node, scope, mode, kind, stack)


_HANDLERS: Final[dict[str, Handler]] = {
    "function_definition": _function,
    "lambda": _lambda,
    "class_definition": _class,
    "named_expression": _walrus,
    "assignment": _assignment,
    "augmented_assignment": _assignment,
    "for_statement": _for_statement,
    "as_pattern": _as_pattern,
    "global_statement": _scope_statement,
    "nonlocal_statement": _scope_statement,
    "attribute": _attribute,
    "keyword_argument": _keyword_argument,
    "import_statement": _import,
    "import_from_statement": _import_from,
    "case_clause": _case_clause,
    "class_pattern": _class_pattern,
    "keyword_pattern": _keyword_pattern,
    "dict_pattern": _dict_pattern,
    "dotted_name": _dotted_name,
    "identifier": _identifier,
    **dict.fromkeys(_COMPREHENSIONS, _comprehension),
}


def bind_python(root: Node, builder: ScopeBuilder) -> None:
    """Walk a Python syntax tree once and feed ``builder`` (the module scope must be open)."""
    stack: list[Frame] = [(root, MODULE_SCOPE, REF, "auto")]
    while stack:
        node, scope, mode, kind = stack.pop()
        handler = _HANDLERS.get(node.type)
        if handler is not None:
            handler(node, scope, mode, kind, builder, stack)
        else:
            _push_children(node, scope, mode, kind, stack)
