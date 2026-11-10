"""Go scoping rules for the symbol table (E07-05).

Owning epic: E07.

``bind_go`` walks the tree once with an explicit stack and feeds a ``ScopeBuilder``; nothing is
resolved here (see ``codekavach.parsing.scopes``). Every name node reaches the builder exactly
once: the handlers classify the ones whose role is not "a use of a name", and any other falls
through to a plain reference.

The rules, in the terms of the language specification:

* the file is the module scope; package-level functions, types, variables and constants are
  declared there, and an import declares its alias (``led``) in it;
* a function, a method and a function literal each open a function scope; the receiver, the
  parameters, the named results and the top-level declarations of the body share that scope;
* a block, an ``if``, a ``for``, a ``switch``, a ``select`` and every ``case`` clause open a block
  scope, so the ``:=`` in an ``if`` initialiser binds for the whole ``if``/``else`` chain and no
  further;
* ``:=`` declares the names on its left in the current scope; ``=`` only uses them; a ``range``
  clause or a ``select`` receive declares only when written with ``:=``;
* a type switch's alias (``switch t := x.(type)``) is declared in the switch's scope;
* struct fields and methods are not names a bare identifier can reach (``e.rate`` is needed), so
  they are declared in a class scope per receiver or struct type that no lookup enters; a selector's
  field, a keyed element's field and a qualified type's member are external occurrences
  (``scope_id == -1``);
* exported names (a leading capital) are a visibility fact, not a public-API fact: they are
  declared like any other name and the classifier decides whether they stay in clear.

A struct literal's keys (``Engine{rate: 3}``) are plain references: the same syntax keys a map by
a variable, and an unresolved reference is the honest answer.
"""

from collections.abc import Callable
from typing import Final

from tree_sitter import Node

from codekavach.parsing.scopes import MODULE_SCOPE, Role, ScopeBuilder, SymbolKind

Frame = tuple[Node, int]

_BLOCK_SCOPED: Final = frozenset(
    {
        "if_statement",
        "for_statement",
        "expression_switch_statement",
        "select_statement",
        "expression_case",
        "default_case",
        "type_case",
        "communication_case",
    }
)
_TYPE_SPECS: Final = frozenset({"type_spec", "type_alias"})
_NAME_TYPES: Final = frozenset({"identifier", "type_identifier"})


def _text(node: Node) -> str:
    return (node.text or b"").decode("utf-8", errors="replace")


class _GoBinder:
    """One walk of one file."""

    def __init__(self, builder: ScopeBuilder) -> None:
        self._builder = builder
        self._stack: list[Frame] = []
        self._containers: dict[str, int] = {}
        self._handlers: dict[str, Callable[[Node, int], None]] = {
            "identifier": self._name,
            "type_identifier": self._name,
            "package_identifier": self._name,
            "field_identifier": self._field,
            "label_name": self._label,
            "package_clause": self._package,
            "import_spec": self._import_spec,
            "type_spec": self._type_spec,
            "type_alias": self._type_spec,
            "struct_type": self._struct_or_interface,
            "interface_type": self._struct_or_interface,
            "field_declaration": self._field_declaration,
            "method_elem": self._method_elem,
            "function_declaration": self._function,
            "method_declaration": self._method,
            "func_literal": self._function_literal,
            "function_type": self._function_type,
            "parameter_declaration": self._parameter,
            "variadic_parameter_declaration": self._parameter,
            "type_parameter_declaration": self._type_parameter,
            "block": self._block,
            "short_var_declaration": self._short_var,
            "var_spec": self._spec,
            "const_spec": self._spec,
            "range_clause": self._declaring_clause,
            "receive_statement": self._declaring_clause,
            "type_switch_statement": self._type_switch,
            "selector_expression": self._selector,
            "qualified_type": self._qualified_type,
            **dict.fromkeys(_BLOCK_SCOPED, self._scoped),
        }

    # --- helpers --------------------------------------------------------------------------

    def _emit(self, node: Node, scope: int, role: Role, kind: SymbolKind = "variable") -> None:
        self._builder.occur(node.start_byte, node.end_byte, _text(node), scope, role, kind)

    def _push(self, nodes: list[Node], scope: int) -> None:
        self._stack.extend((child, scope) for child in reversed(nodes))

    def _push_children(self, node: Node, scope: int) -> None:
        self._push(node.named_children, scope)

    def _push_except(self, node: Node, skip: list[Node], scope: int) -> None:
        skipped = {(item.start_byte, item.end_byte) for item in skip}
        self._push(
            [c for c in node.named_children if (c.start_byte, c.end_byte) not in skipped], scope
        )

    def _container(self, name: str) -> int:
        """The class scope that holds the fields and methods of the type ``name``."""
        found = self._containers.get(name)
        if found is None:
            found = self._builder.open("class", MODULE_SCOPE)
            self._containers[name] = found
        return found

    def _define_names(self, names: list[Node], scope: int, kind: SymbolKind) -> None:
        for name in names:
            if _text(name) == "_":
                self._emit(name, scope, "external", kind)
            else:
                self._emit(name, scope, "define", kind)

    # --- names ----------------------------------------------------------------------------

    def _name(self, node: Node, scope: int) -> None:
        if _text(node) == "_":
            self._emit(node, scope, "external")
        elif node.type == "type_identifier":
            self._emit(node, scope, "reference", "class")
        else:
            self._emit(node, scope, "reference")

    def _field(self, node: Node, scope: int) -> None:
        self._emit(node, scope, "external", "field")

    def _label(self, node: Node, scope: int) -> None:
        self._emit(node, scope, "external")

    def _selector(self, node: Node, scope: int) -> None:
        field = node.child_by_field_name("field")
        for child in node.named_children:
            if field is not None and child == field:
                self._emit(child, scope, "external", "field")
            else:
                self._stack.append((child, scope))

    def _qualified_type(self, node: Node, scope: int) -> None:
        for child in node.named_children:
            if child.type == "type_identifier":
                self._emit(child, scope, "external", "class")
            else:
                self._stack.append((child, scope))

    # --- file level -----------------------------------------------------------------------

    def _package(self, node: Node, scope: int) -> None:
        for child in node.named_children:
            self._emit(child, scope, "external", "module")

    def _import_spec(self, node: Node, scope: int) -> None:
        name = node.child_by_field_name("name")
        for child in node.named_children:
            if name is not None and child == name and child.type == "package_identifier":
                self._emit(child, MODULE_SCOPE, "define", "import")
            elif name is not None and child == name:
                continue  # the blank identifier and the dot import bind no name
            else:
                self._stack.append((child, scope))

    # --- types ----------------------------------------------------------------------------

    def _type_spec(self, node: Node, scope: int) -> None:
        name = node.child_by_field_name("name")
        inner = scope
        if name is not None:
            self._emit(name, scope, "define", "class")
            self._builder.extent(name.start_byte, node.start_byte, node.end_byte)
        if any(c.type == "type_parameter_list" for c in node.named_children):
            inner = self._builder.open("block", scope)
        for child in node.named_children:
            if name is not None and child == name:
                continue
            self._stack.append((child, inner))

    def _struct_or_interface(self, node: Node, scope: int) -> None:
        parent = node.parent
        owner = parent.child_by_field_name("name") if parent is not None else None
        if parent is not None and parent.type in _TYPE_SPECS and owner is not None:
            inner = self._container(_text(owner))
        else:
            inner = self._builder.open("class", scope)
        self._push_children(node, inner)

    def _field_declaration(self, node: Node, scope: int) -> None:
        names = node.children_by_field_name("name")
        in_class = self._builder.kind_of(scope) == "class"
        for name in names:
            self._emit(name, scope, "define" if in_class else "external", "field")
        self._push_except(node, names, scope)

    def _method_elem(self, node: Node, scope: int) -> None:
        name = node.child_by_field_name("name")
        function = self._builder.open("function", scope)
        if name is not None:
            self._emit(name, scope, "define", "method")
        self._push_except(node, [name] if name is not None else [], function)

    def _type_parameter(self, node: Node, scope: int) -> None:
        names = node.children_by_field_name("name")
        self._define_names(names, scope, "class")
        self._push_except(node, names, scope)

    # --- functions ------------------------------------------------------------------------

    def _body(self, node: Node, function: int, skip: list[Node]) -> None:
        """Push the parts of a function; its body shares the function's scope."""
        for child in reversed(node.named_children):
            if any(child == item for item in skip):
                continue
            if child.type == "block":
                self._push_children(child, function)
            else:
                self._stack.append((child, function))

    def _function(self, node: Node, scope: int) -> None:
        name = node.child_by_field_name("name")
        function = self._builder.open("function", scope)
        if name is not None:
            self._emit(name, scope, "define", "function")
            self._builder.extent(name.start_byte, node.start_byte, node.end_byte)
        self._body(node, function, [name] if name is not None else [])

    def _function_literal(self, node: Node, scope: int) -> None:
        self._body(node, self._builder.open("function", scope), [])

    def _function_type(self, node: Node, scope: int) -> None:
        self._push_children(node, self._builder.open("function", scope))

    def _receiver_base(self, method: Node) -> str:
        receiver = method.child_by_field_name("receiver")
        if receiver is None:
            return ""
        stack = [receiver]
        while stack:
            current = stack.pop()
            if current.type == "type_identifier":
                return _text(current)
            stack.extend(reversed(current.named_children))
        return ""

    def _method(self, node: Node, scope: int) -> None:
        name = node.child_by_field_name("name")
        function = self._builder.open("function", scope)
        if name is not None:
            self._emit(name, self._container(self._receiver_base(node)), "define", "method")
            self._builder.extent(name.start_byte, node.start_byte, node.end_byte)
        self._body(node, function, [name] if name is not None else [])

    def _parameter(self, node: Node, scope: int) -> None:
        names = node.children_by_field_name("name")
        self._define_names(names, scope, "parameter")
        self._push_except(node, names, scope)

    # --- statements -----------------------------------------------------------------------

    def _block(self, node: Node, scope: int) -> None:
        self._push_children(node, self._builder.open("block", scope))

    def _scoped(self, node: Node, scope: int) -> None:
        self._push_children(node, self._builder.open("block", scope))

    def _short_var(self, node: Node, scope: int) -> None:
        left = node.child_by_field_name("left")
        names = [] if left is None else [c for c in left.named_children if c.type == "identifier"]
        self._define_names(names, scope, "variable")
        self._push_except(node, names + ([left] if left is not None else []), scope)
        if left is not None:
            self._push([c for c in left.named_children if c.type != "identifier"], scope)

    def _spec(self, node: Node, scope: int) -> None:
        names = node.children_by_field_name("name")
        kind: SymbolKind = "constant" if node.type == "const_spec" else "variable"
        self._define_names(names, scope, kind)
        self._push_except(node, names, scope)

    def _declaring_clause(self, node: Node, scope: int) -> None:
        """``for k, v := range x`` and ``case v := <-ch``: declare only with ``:=``."""
        left = node.child_by_field_name("left")
        declares = any(child.type == ":=" for child in node.children)
        if left is None or not declares:
            self._push_children(node, scope)
            return
        names = [c for c in left.named_children if c.type == "identifier"]
        self._define_names(names, scope, "variable")
        self._push_except(node, [left], scope)
        self._push([c for c in left.named_children if c.type != "identifier"], scope)

    def _type_switch(self, node: Node, scope: int) -> None:
        inner = self._builder.open("block", scope)
        alias = node.child_by_field_name("alias")
        if alias is not None:
            self._define_names(
                [c for c in alias.named_children if c.type == "identifier"], inner, "variable"
            )
        self._push_except(node, [alias] if alias is not None else [], inner)

    # --- the walk -------------------------------------------------------------------------

    def run(self, root: Node) -> None:
        self._stack.append((root, MODULE_SCOPE))
        while self._stack:
            node, scope = self._stack.pop()
            handler = self._handlers.get(node.type)
            if handler is not None:
                handler(node, scope)
            else:
                self._push_children(node, scope)


def bind_go(root: Node, builder: ScopeBuilder) -> None:
    """Feed ``builder`` the scopes and identifier occurrences of the tree rooted at ``root``."""
    _GoBinder(builder).run(root)
