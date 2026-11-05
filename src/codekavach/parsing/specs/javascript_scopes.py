"""JavaScript and TypeScript scoping rules for the symbol table (E07-03).

Owning epic: E07.

``bind_javascript`` walks the tree once with an explicit stack and feeds a ``ScopeBuilder``;
nothing is resolved here (see ``codekavach.parsing.scopes``). Every identifier-typed node reaches
the builder exactly once: the handlers classify the ones that are not "a use of a name", and any
other falls through to a plain reference.

The rules, in the terms of the language specification:

* a module (or script) scope; a function scope for parameters, ``var`` and the function's own
  top-level declarations; a block scope for ``let``, ``const`` and ``class`` (the temporal dead
  zone is treated as "bound in this block", which is all renaming needs);
* ``var`` and function declarations hoist: they are recorded in the nearest function scope and the
  two-phase builder resolves uses that come before them;
* a ``catch`` parameter, a ``for`` header and a ``switch`` body each get their own block scope;
* arrow functions are function scopes that bind no ``this`` or ``arguments`` (neither is an
  identifier node, so there is nothing to bind);
* class members (fields, methods, getters, setters, TypeScript interface and enum members) are
  declared in a class scope that lexical lookup skips, because a bare name inside a method never
  means a member; ``obj.member`` is an external occurrence (``scope_id == -1``) of kind ``field``;
* declaration patterns bind, assignment patterns only use: ``const {a} = o`` defines ``a``,
  ``({a} = o)`` refers to an existing ``a``; an assignment to an undeclared name stays unresolved
  rather than inventing an implicit global.

TypeScript adds type-level names (interfaces, type aliases, enums, generics). They live in the
same scopes, with kind ``class`` for the type names a program can rename.
"""

from collections.abc import Callable
from typing import Final, cast

from tree_sitter import Node

from codekavach.parsing.scopes import MODULE_SCOPE, Role, ScopeBuilder, SymbolKind

REF: Final = 0
BIND: Final = 1
ASSIGN: Final = 2
IMPORT: Final = 3

# node, scope the occurrence appears in, mode, scope a binding is made in, kind hint
Frame = tuple[Node, int, int, int, str]
Handler = Callable[[Node, int, int, int, str, ScopeBuilder, list[Frame]], None]

_PROPERTY_NAMES: Final = frozenset({"property_identifier", "private_property_identifier"})
_FUNCTION_DECLARATIONS: Final = frozenset(
    {"function_declaration", "generator_function_declaration", "function_signature"}
)
_FUNCTION_EXPRESSIONS: Final = frozenset({"function_expression", "function", "generator_function"})
_METHODS: Final = frozenset({"method_definition", "method_signature", "abstract_method_signature"})
_CLASS_DECLARATIONS: Final = frozenset({"class_declaration", "abstract_class_declaration"})
_FUNCTION_VALUES: Final = frozenset({"arrow_function", *_FUNCTION_EXPRESSIONS})
_PATTERN_CONTAINERS: Final = frozenset({"array_pattern", "rest_pattern"})


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
    builder: ScopeBuilder, node: Node, scope: int, role: Role, kind: SymbolKind = "variable"
) -> None:
    builder.occur(node.start_byte, node.end_byte, _text(node), scope, role, kind)


def _declared_kind(hint: str, name: str) -> SymbolKind:
    if hint == "const":
        return "constant" if name.isupper() else "variable"
    if hint == "plain":
        return "variable"
    return cast(SymbolKind, hint)


def _define(builder: ScopeBuilder, node: Node, bind_scope: int, hint: str) -> None:
    name = _text(node)
    builder.occur(
        node.start_byte, node.end_byte, name, bind_scope, "define", _declared_kind(hint, name)
    )


def _push_children(
    node: Node, scope: int, mode: int, bind: int, hint: str, stack: list[Frame]
) -> None:
    child_mode = mode if mode == IMPORT or node.type in _PATTERN_CONTAINERS else REF
    stack.extend((child, scope, child_mode, bind, hint) for child in reversed(node.named_children))


def _identifier(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    if mode == BIND:
        _define(builder, node, bind, hint)
    elif mode == IMPORT:
        _define(builder, node, scope, "import")
    else:
        _emit(builder, node, scope, "reference")


def _property(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    _emit(builder, node, scope, "external", "field")


def _label(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    _emit(builder, node, scope, "external", "variable")


def _shorthand_pattern(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    if mode == BIND:
        _define(builder, node, bind, hint)
    else:
        _emit(builder, node, scope, "reference")


def _member_name(
    builder: ScopeBuilder, name: Node, scope: int, kind: SymbolKind, stack: list[Frame]
) -> None:
    """A member's name: declared in a class scope, otherwise an external occurrence."""
    if name.type in _PROPERTY_NAMES:
        role: Role = "define" if builder.kind_of(scope) == "class" else "external"
        _emit(builder, name, scope, role, kind)
    elif name.type == "computed_property_name":
        stack.append((name, scope, REF, scope, "plain"))


def _push_type_parameters(node: Node, target: int, stack: list[Frame]) -> None:
    for parameter in node.named_children:
        if parameter.type != "type_parameter":
            continue
        for child, field in _fielded(parameter):
            if field == "name":
                stack.append((child, target, BIND, target, "class"))
            else:
                stack.append((child, target, REF, target, "plain"))


def _push_parameters(parameters: Node, inner: int, stack: list[Frame]) -> None:
    """Bind parameters in ``inner``.

    Their types and defaults are read there as well, so that a type annotation can name the
    function's own type parameters.
    """
    for child in parameters.named_children:
        if child.type in ("required_parameter", "optional_parameter"):
            for sub, field in _fielded(child):
                if field == "pattern":
                    stack.append((sub, inner, BIND, inner, "parameter"))
                else:
                    stack.append((sub, inner, REF, inner, "plain"))
        else:
            stack.append((child, inner, BIND, inner, "parameter"))


def _push_body(body: Node, inner: int, stack: list[Frame]) -> None:
    """A function body shares the function's scope; a block body must not open another."""
    if body.type == "statement_block":
        stack.extend((child, inner, REF, inner, "plain") for child in reversed(body.named_children))
    else:
        stack.append((body, inner, REF, inner, "plain"))


def _function(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    inner = builder.open("function", scope)
    for child, field in _fielded(node):
        if field == "name":
            if node.type in _FUNCTION_DECLARATIONS:
                _emit(builder, child, scope, "define", "function")
                builder.extent(child.start_byte, node.start_byte, node.end_byte)
            elif node.type in _FUNCTION_EXPRESSIONS:
                _emit(builder, child, inner, "define", "function")
            elif node.type in _METHODS:
                _member_name(builder, child, scope, "method", stack)
                if child.type in _PROPERTY_NAMES and builder.kind_of(scope) == "class":
                    builder.extent(child.start_byte, node.start_byte, node.end_byte)
        elif field == "parameters":
            _push_parameters(child, inner, stack)
        elif field == "parameter":
            stack.append((child, inner, BIND, inner, "parameter"))
        elif field == "type_parameters":
            _push_type_parameters(child, inner, stack)
        elif field == "body":
            _push_body(child, inner, stack)
        elif field == "return_type":
            stack.append((child, inner, REF, inner, "plain"))
        else:  # decorators
            stack.append((child, scope, REF, scope, "plain"))


def _generic_scope(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> int:
    """The scope a generic declaration's heritage and body see: ``scope`` plus its type parameters.

    Type parameters get a block scope of their own, between the declaration's scope and its class
    scope, because lexical lookup skips class scopes and ``T`` must stay visible in the body.
    """
    parameters = node.child_by_field_name("type_parameters")
    if parameters is None:
        return scope
    generic = builder.open("block", scope)
    _push_type_parameters(parameters, generic, stack)
    return generic


def _class(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    outer = _generic_scope(node, scope, builder, stack)
    is_declaration = node.type in _CLASS_DECLARATIONS
    if not is_declaration and outer == scope and node.child_by_field_name("name") is not None:
        # a class expression's own name is visible in its methods, which skip the class scope
        outer = builder.open("block", scope)
    inner = builder.open("class", outer)
    for child, field in _fielded(node):
        if field == "name":
            declared_in = scope if is_declaration else outer
            _emit(builder, child, declared_in, "define", "class")
            if is_declaration:
                builder.extent(child.start_byte, node.start_byte, node.end_byte)
        elif field == "type_parameters":
            continue
        elif field == "body":
            stack.append((child, inner, REF, inner, "plain"))
        else:  # heritage clauses and decorators are evaluated outside the class body
            stack.append((child, outer, REF, outer, "plain"))


def _interface(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    outer = _generic_scope(node, scope, builder, stack)
    inner = builder.open("class", outer)
    for child, field in _fielded(node):
        if field == "name":
            _emit(builder, child, scope, "define", "class")
            builder.extent(child.start_byte, node.start_byte, node.end_byte)
        elif field == "type_parameters":
            continue
        elif field == "body":
            stack.append((child, inner, REF, inner, "plain"))
        else:
            stack.append((child, outer, REF, outer, "plain"))


def _enum(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    inner = builder.open("class", scope)
    for child, field in _fielded(node):
        if field == "name":
            _emit(builder, child, scope, "define", "class")
            builder.extent(child.start_byte, node.start_byte, node.end_byte)
        elif field == "body":
            for member, member_field in _fielded(child):
                if member.type in _PROPERTY_NAMES:
                    _emit(builder, member, inner, "define", "field")
                elif member.type == "enum_assignment":
                    for part, part_field in _fielded(member):
                        if part_field == "name" and part.type in _PROPERTY_NAMES:
                            _emit(builder, part, inner, "define", "field")
                        else:
                            stack.append((part, inner, REF, inner, "plain"))
                else:
                    stack.append((member, inner, REF, inner, "plain"))
                _ = member_field
        else:
            stack.append((child, scope, REF, scope, "plain"))


def _type_alias(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    inner = builder.open("block", scope)
    for child, field in _fielded(node):
        if field == "name":
            _emit(builder, child, scope, "define", "class")
        elif field == "type_parameters":
            _push_type_parameters(child, inner, stack)
        else:
            stack.append((child, inner, REF, inner, "plain"))


def _module(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, field in _fielded(node):
        if field == "name" and child.type == "identifier":
            _emit(builder, child, scope, "define", "module")
        else:
            stack.append((child, scope, REF, scope, "plain"))


def _field_definition(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, field in _fielded(node):
        if field in ("property", "name"):
            _member_name(builder, child, scope, "field", stack)
        else:
            stack.append((child, scope, REF, scope, "plain"))


def _signature_member(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    """``property_signature`` of an interface or a type literal."""
    _field_definition(node, scope, mode, bind, hint, builder, stack)


def _variable_declaration(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    is_var = node.type == "variable_declaration"
    keyword = node.child_by_field_name("kind")
    is_const = keyword is not None and _text(keyword) == "const"
    target = builder.enclosing_function(scope) if is_var else scope
    declaration_hint = "const" if is_const else "plain"
    for child in node.named_children:
        if child.type == "variable_declarator":
            stack.append((child, scope, REF, target, declaration_hint))
        else:
            stack.append((child, scope, REF, scope, "plain"))


def _variable_declarator(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    name = node.child_by_field_name("name")
    value = node.child_by_field_name("value")
    for child, field in _fielded(node):
        if field == "name":
            stack.append((child, scope, BIND, bind, hint))
        else:
            stack.append((child, scope, REF, scope, "plain"))
    if (
        name is not None
        and value is not None
        and name.type == "identifier"
        and value.type in _FUNCTION_VALUES
    ):
        builder.extent(name.start_byte, value.start_byte, value.end_byte)


def _assignment(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, field in _fielded(node):
        if field == "left":
            stack.append((child, scope, ASSIGN, scope, "plain"))
        else:
            stack.append((child, scope, REF, scope, "plain"))


def _object_pattern(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, _ in _fielded(node):
        stack.append((child, scope, mode, bind, hint))


def _pair_pattern(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, field in _fielded(node):
        if field == "key":
            if child.type in _PROPERTY_NAMES:
                _emit(builder, child, scope, "external", "field")
            else:
                stack.append((child, scope, REF, scope, "plain"))
        else:
            stack.append((child, scope, mode, bind, hint))


def _pattern_with_default(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, field in _fielded(node):
        if field == "right":
            stack.append((child, scope, REF, scope, "plain"))
        else:
            stack.append((child, scope, mode, bind, hint))


def _member_expression(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, field in _fielded(node):
        if field == "property" and child.type in _PROPERTY_NAMES:
            _emit(builder, child, scope, "external", "field")
        else:
            stack.append((child, scope, REF, scope, "plain"))


def _pair(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child, field in _fielded(node):
        if field == "key" and child.type in _PROPERTY_NAMES:
            _emit(builder, child, scope, "external", "field")
        else:
            stack.append((child, scope, REF, scope, "plain"))


def _block(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    inner = builder.open("block", scope)
    stack.extend((child, inner, REF, inner, "plain") for child in reversed(node.named_children))


def _for(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    inner = builder.open("block", scope)
    stack.extend((child, inner, REF, inner, "plain") for child in reversed(node.named_children))


def _for_in(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    inner = builder.open("block", scope)
    keyword = node.child_by_field_name("kind")
    word = _text(keyword) if keyword is not None else ""
    for child, field in _fielded(node):
        if field == "left" and word:
            target = builder.enclosing_function(inner) if word == "var" else inner
            stack.append((child, inner, BIND, target, "const" if word == "const" else "plain"))
        elif field == "left":
            stack.append((child, inner, ASSIGN, inner, "plain"))
        else:
            stack.append((child, inner, REF, inner, "plain"))


def _catch(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    inner = builder.open("block", scope)
    for child, field in _fielded(node):
        if field == "parameter":
            stack.append((child, inner, BIND, inner, "plain"))
        else:
            stack.append((child, inner, REF, inner, "plain"))


def _import_specifier(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    has_alias = node.child_by_field_name("alias") is not None
    for child, field in _fielded(node):
        if field == "alias" or not has_alias:
            _emit(builder, child, scope, "define", "import")
        else:
            _emit(builder, child, scope, "external", "import")


def _import_statement(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    for child in reversed(node.named_children):
        is_clause = child.type in ("import_clause", "import_require_clause")
        stack.append((child, scope, IMPORT if is_clause else REF, scope, "plain"))


def _export_specifier(
    node: Node,
    scope: int,
    mode: int,
    bind: int,
    hint: str,
    builder: ScopeBuilder,
    stack: list[Frame],
) -> None:
    statement = node.parent.parent if node.parent is not None else None
    reexport = statement is not None and statement.child_by_field_name("source") is not None
    for child, field in _fielded(node):
        if field == "alias":
            _emit(builder, child, scope, "external", "field")
        elif reexport:
            _emit(builder, child, scope, "external", "import")
        else:
            _emit(builder, child, scope, "reference")


_HANDLERS: Final[dict[str, Handler]] = {
    "identifier": _identifier,
    "type_identifier": _identifier,
    "property_identifier": _property,
    "private_property_identifier": _property,
    "statement_identifier": _label,
    "shorthand_property_identifier": _identifier,
    "shorthand_property_identifier_pattern": _shorthand_pattern,
    "statement_block": _block,
    "switch_body": _block,
    "for_statement": _for,
    "for_in_statement": _for_in,
    "catch_clause": _catch,
    "arrow_function": _function,
    "class": _class,
    "class_declaration": _class,
    "abstract_class_declaration": _class,
    "interface_declaration": _interface,
    "enum_declaration": _enum,
    "type_alias_declaration": _type_alias,
    "internal_module": _module,
    "module": _module,
    "field_definition": _field_definition,
    "public_field_definition": _field_definition,
    "property_signature": _signature_member,
    "variable_declaration": _variable_declaration,
    "lexical_declaration": _variable_declaration,
    "variable_declarator": _variable_declarator,
    "assignment_expression": _assignment,
    "augmented_assignment_expression": _assignment,
    "object_pattern": _object_pattern,
    "pair_pattern": _pair_pattern,
    "assignment_pattern": _pattern_with_default,
    "object_assignment_pattern": _pattern_with_default,
    "member_expression": _member_expression,
    "pair": _pair,
    "import_statement": _import_statement,
    "import_specifier": _import_specifier,
    "export_specifier": _export_specifier,
    **dict.fromkeys(_FUNCTION_DECLARATIONS, _function),
    **dict.fromkeys(_FUNCTION_EXPRESSIONS, _function),
    **dict.fromkeys(_METHODS, _function),
}


def bind_javascript(root: Node, builder: ScopeBuilder) -> None:
    """Walk a JavaScript or TypeScript tree once and feed ``builder`` (module scope open)."""
    stack: list[Frame] = [(root, MODULE_SCOPE, REF, MODULE_SCOPE, "plain")]
    while stack:
        node, scope, mode, bind, hint = stack.pop()
        handler = _HANDLERS.get(node.type)
        if handler is not None:
            handler(node, scope, mode, bind, hint, builder, stack)
        else:
            _push_children(node, scope, mode, bind, hint, stack)
