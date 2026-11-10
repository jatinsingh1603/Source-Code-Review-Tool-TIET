"""Java scoping rules for the symbol table (E07-05).

Owning epic: E07.

``bind_java`` walks the tree once with an explicit stack and feeds a ``ScopeBuilder``; nothing is
resolved here (see ``codekavach.parsing.scopes``). Every ``identifier`` and ``type_identifier``
node reaches the builder exactly once: the handlers classify the ones whose role is not "a use of
a name", and any other falls through to a plain reference.

The rules, in the terms of the language specification:

* the compilation unit is the module scope; a type declaration (class, interface, enum, record,
  annotation type, and an anonymous class body) opens a class scope whose members are visible to
  every method nested in it, so a bare ``rate`` inside a method resolves to the field;
* a method, a constructor, an initialiser block and a lambda each open a function scope; the
  parameters and the top-level locals of a method body share that one scope;
* a block, a ``for`` header, a ``try``-with-resources and a ``catch`` clause each open a block
  scope; a pattern variable (``o instanceof Account a``, ``case String s``) binds in the scope it
  appears in, which is wider than its flow scope and enough for renaming;
* a type parameter is declared in the scope of the type or method that declares it;
* ``obj.member``, ``this.member``, a method called on an object, a method reference's method name,
  an annotation element name and a label are external occurrences (``scope_id == -1``); a name
  after a dot in a qualified type is external too, because it is resolved by the package layout;
* an import declares the simple name it imports in the module scope; the package path is
  external, so ``java`` in ``java.util.List`` is never a variable.

A constructor's name is a use of the class name, not a new declaration.
"""

from collections.abc import Callable
from typing import Final

from tree_sitter import Node

from codekavach.parsing.scopes import MODULE_SCOPE, Role, ScopeBuilder, SymbolKind

Frame = tuple[Node, int]
Handler = Callable[[Node, int, ScopeBuilder, list[Frame]], None]

_TYPE_DECLARATIONS: Final = frozenset(
    {
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "annotation_type_declaration",
    }
)
_METHOD_LIKE: Final = frozenset(
    {"method_declaration", "annotation_type_element_declaration", "constructor_declaration"}
)
_INITIALISER_PARENTS: Final = frozenset(
    {"class_body", "static_initializer", "enum_body_declarations"}
)
_IDENTIFIERS: Final = frozenset({"identifier", "type_identifier"})


def _text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")


def _emit(
    builder: ScopeBuilder, node: Node, scope: int, role: Role, kind: SymbolKind = "variable"
) -> None:
    builder.occur(node.start_byte, node.end_byte, _text(node), scope, role, kind)


def _push(nodes: list[Node], scope: int, stack: list[Frame]) -> None:
    stack.extend((child, scope) for child in reversed(nodes))


def _push_children(node: Node, scope: int, stack: list[Frame]) -> None:
    _push(node.named_children, scope, stack)


def _leaves(node: Node) -> list[Node]:
    """The identifier leaves of a qualified name, left to right."""
    if node.type in _IDENTIFIERS:
        return [node]
    found: list[Node] = []
    for child in node.named_children:
        found.extend(_leaves(child))
    return found


def _constant_or(name: str, default: SymbolKind) -> SymbolKind:
    return "constant" if name.isupper() and len(name) > 1 else default


# --- names ---------------------------------------------------------------------------------------


def _identifier(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    _emit(builder, node, scope, "reference")


def _qualified(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    """``a.b.C`` in a type or an annotation: the first name is a use, the rest are external."""
    leaves = _leaves(node)
    for index, leaf in enumerate(leaves):
        if index == 0:
            _emit(builder, leaf, scope, "reference", "class")
        else:
            _emit(builder, leaf, scope, "external", "class")


def _field_access(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    for child in node.named_children:
        if node.child_by_field_name("field") == child:
            _emit(builder, child, scope, "external", "field")
        else:
            stack.append((child, scope))


def _method_invocation(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    receiver = node.child_by_field_name("object")
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            if receiver is None:
                _emit(builder, child, scope, "reference", "method")
            else:
                _emit(builder, child, scope, "external", "method")
        else:
            stack.append((child, scope))


def _method_reference(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    children = node.named_children
    for index, child in enumerate(children):
        if index == len(children) - 1 and index > 0 and child.type == "identifier":
            _emit(builder, child, scope, "external", "method")
        else:
            stack.append((child, scope))


def _label(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    """A labelled statement names its label first; ``break``/``continue`` name one."""
    for index, child in enumerate(node.named_children):
        if child.type == "identifier" and (node.type != "labeled_statement" or index == 0):
            _emit(builder, child, scope, "external", "variable")
        else:
            stack.append((child, scope))


def _annotation(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            if child.type == "identifier":
                _emit(builder, child, scope, "reference", "class")
            else:
                _qualified(child, scope, builder, stack)
        else:
            stack.append((child, scope))


def _element_value_pair(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    key = node.child_by_field_name("key")
    for child in node.named_children:
        if key is not None and child == key:
            _emit(builder, child, scope, "external", "field")
        else:
            stack.append((child, scope))


# --- the compilation unit ------------------------------------------------------------------------


def _package(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    for leaf in _leaves(node):
        _emit(builder, leaf, scope, "external", "module")


def _import(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    leaves = _leaves(node)
    wildcard = any(child.type == "asterisk" for child in node.children)
    for index, leaf in enumerate(leaves):
        if index == len(leaves) - 1 and not wildcard:
            _emit(builder, leaf, MODULE_SCOPE, "define", "import")
        else:
            _emit(builder, leaf, scope, "external", "module")


# --- declarations --------------------------------------------------------------------------------


def _type_parameter(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    named = node.named_children
    for index, child in enumerate(named):
        if index == 0 and child.type == "type_identifier":
            _emit(builder, child, scope, "define", "class")
        else:
            stack.append((child, scope))


def _type_declaration(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    inner = builder.open("class", scope)
    if name is not None:
        _emit(builder, name, scope, "define", "class")
        builder.extent(name.start_byte, node.start_byte, node.end_byte)
    for child in node.named_children:
        if name is not None and child == name:
            continue
        if child.type == "formal_parameters" and node.type == "record_declaration":
            _record_components(child, inner, builder, stack)
        else:
            stack.append((child, inner))


def _record_components(
    parameters: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    """Record components are fields of the record, declared in its class scope."""
    for component in parameters.named_children:
        name = component.child_by_field_name("name")
        for child in component.named_children:
            if name is not None and child == name:
                _emit(builder, child, scope, "define", "field")
            else:
                stack.append((child, scope))


def _object_creation(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    for child in node.named_children:
        if child.type == "class_body":
            stack.append((child, builder.open("class", scope)))
        else:
            stack.append((child, scope))


def _enum_constant(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            _emit(builder, child, scope, "define", "constant")
        elif child.type == "class_body":
            stack.append((child, builder.open("class", scope)))
        else:
            stack.append((child, scope))


def _variable_declarator(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    in_class = builder.kind_of(scope) == "class"
    for child in node.named_children:
        if name is not None and child == name:
            default: SymbolKind = "field" if in_class else "variable"
            _emit(builder, child, scope, "define", _constant_or(_text(child), default))
        else:
            stack.append((child, scope))


def _parameter(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    """A formal, catch or spread parameter: the declared name binds in ``scope``."""
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            _emit(builder, child, scope, "define", "parameter")
        elif node.type == "spread_parameter" and child.type == "variable_declarator":
            inner = child.child_by_field_name("name")
            for sub in child.named_children:
                if inner is not None and sub == inner:
                    _emit(builder, sub, scope, "define", "parameter")
                else:
                    stack.append((sub, scope))
        else:
            stack.append((child, scope))


def _function_parts(
    node: Node, function: int, outer: int, builder: ScopeBuilder, stack: list[Frame]
) -> None:
    """Push the parts of a method or constructor; its body shares the function scope."""
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            continue
        if child.type in ("block", "constructor_body"):
            _push_children(child, function, stack)
        elif child.type == "modifiers":
            stack.append((child, outer))
        else:
            stack.append((child, function))


def _method(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    function = builder.open("function", scope)
    if name is not None:
        if node.type == "constructor_declaration":
            _emit(builder, name, scope, "reference", "class")
        else:
            _emit(builder, name, scope, "define", "method")
        builder.extent(name.start_byte, node.start_byte, node.end_byte)
    _function_parts(node, function, scope, builder, stack)


def _compact_constructor(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    function = builder.open("function", scope)
    if name is not None:
        _emit(builder, name, scope, "reference", "class")
        builder.extent(name.start_byte, node.start_byte, node.end_byte)
    _function_parts(node, function, scope, builder, stack)


def _lambda(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    function = builder.open("function", scope)
    for child in node.named_children:
        if child.type == "identifier" and node.child_by_field_name("parameters") == child:
            _emit(builder, child, function, "define", "parameter")
        elif child.type == "inferred_parameters":
            for sub in child.named_children:
                _emit(builder, sub, function, "define", "parameter")
        elif child.type == "block":
            _push_children(child, function, stack)
        else:
            stack.append((child, function))


# --- statements ----------------------------------------------------------------------------------


def _block(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    parent = node.parent
    if parent is not None and parent.type in _INITIALISER_PARENTS:
        inner = builder.open("function", scope)
    else:
        inner = builder.open("block", scope)
    _push_children(node, inner, stack)


def _static_initializer(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    _push_children(node, scope, stack)


def _scoped(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    """A construct that owns a block scope for its header and parts."""
    _push_children(node, builder.open("block", scope), stack)


def _enhanced_for(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    inner = builder.open("block", scope)
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            _emit(builder, child, inner, "define", "variable")
        else:
            stack.append((child, inner))


def _resource(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            _emit(builder, child, scope, "define", "variable")
        else:
            stack.append((child, scope))


def _instanceof(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    name = node.child_by_field_name("name")
    for child in node.named_children:
        if name is not None and child == name:
            _emit(builder, child, scope, "define", "variable")
        else:
            stack.append((child, scope))


def _type_pattern(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    """``String s``: the type is a use, the last identifier is the bound name."""
    children = node.named_children
    for index, child in enumerate(children):
        if index == len(children) - 1 and child.type == "identifier":
            _emit(builder, child, scope, "define", "variable")
        else:
            stack.append((child, scope))


def _record_pattern(node: Node, scope: int, builder: ScopeBuilder, stack: list[Frame]) -> None:
    for index, child in enumerate(node.named_children):
        if index == 0 and child.type == "identifier":
            _emit(builder, child, scope, "reference", "class")
        else:
            stack.append((child, scope))


_HANDLERS: Final[dict[str, Handler]] = {
    "identifier": _identifier,
    "type_identifier": _identifier,
    "scoped_identifier": _qualified,
    "scoped_type_identifier": _qualified,
    "field_access": _field_access,
    "method_invocation": _method_invocation,
    "method_reference": _method_reference,
    "labeled_statement": _label,
    "break_statement": _label,
    "continue_statement": _label,
    "annotation": _annotation,
    "marker_annotation": _annotation,
    "element_value_pair": _element_value_pair,
    "package_declaration": _package,
    "import_declaration": _import,
    "type_parameter": _type_parameter,
    "object_creation_expression": _object_creation,
    "enum_constant": _enum_constant,
    "variable_declarator": _variable_declarator,
    "formal_parameter": _parameter,
    "spread_parameter": _parameter,
    "catch_formal_parameter": _parameter,
    "compact_constructor_declaration": _compact_constructor,
    "lambda_expression": _lambda,
    "block": _block,
    "static_initializer": _static_initializer,
    "for_statement": _scoped,
    "catch_clause": _scoped,
    "try_with_resources_statement": _scoped,
    "enhanced_for_statement": _enhanced_for,
    "resource": _resource,
    "instanceof_expression": _instanceof,
    "type_pattern": _type_pattern,
    "record_pattern": _record_pattern,
    **dict.fromkeys(_TYPE_DECLARATIONS, _type_declaration),
    **dict.fromkeys(_METHOD_LIKE, _method),
}


def bind_java(root: Node, builder: ScopeBuilder) -> None:
    """Feed ``builder`` the scopes and identifier occurrences of the tree rooted at ``root``."""
    stack: list[Frame] = [(root, MODULE_SCOPE)]
    while stack:
        node, scope = stack.pop()
        handler = _HANDLERS.get(node.type)
        if handler is not None:
            handler(node, scope, builder, stack)
        else:
            _push_children(node, scope, stack)
