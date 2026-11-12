"""A table-driven scope binder shared by the Kotlin, PHP, C#, Ruby, C and C++ specs (E07-05b).

Owning epic: E07.

The Java, Go, Python and JavaScript binders are written by hand, one function per grammar quirk.
These six grammars are bound by the same walk instead, parameterised by a ``Rules`` record that
says, per node type, which child nodes are *names* and what the node does with them:

* a **type** (class, struct, interface, enum, object, trait, module) declares its name in the
  enclosing scope and opens a class scope for its body;
* a **function** declares its name in the enclosing scope and opens a function scope that holds the
  parameters and the top-level locals of the body (a body block merges into the function scope);
* a **lambda** opens a function scope without a name;
* a **block** opens a block scope;
* a **declaration** (parameter, local, field, enum constant, import alias) declares its names;
* a **member** (``obj.name``, ``Type::name``, a keyword argument) holds names that no lexical
  lookup can resolve: they are external occurrences (``scope_id == -1``);
* an **assignment** in a dynamic language declares a plain left-hand name in the current scope.

Nothing is resolved here (see ``codekavach.parsing.scopes``). Every name node reaches the builder
exactly once: a name a handler claims is emitted by the handler and skipped when the children are
pushed; any other leaf of a name type falls through to a plain reference.
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from tree_sitter import Node

from codekavach.parsing.scopes import MODULE_SCOPE, Role, ScopeBuilder, SymbolKind

Frame = tuple[Node, int]
Names = Callable[[Node], list[Node]]
KindOf = Callable[[Node, ScopeBuilder, int], SymbolKind]


def text_of(node: Node) -> str:
    """The UTF-8 text of ``node``."""
    return (node.text or b"").decode("utf-8", errors="replace")


def leaves(node: Node | None, types: frozenset[str]) -> list[Node]:
    """The name leaves under ``node`` (or ``node`` itself), left to right."""
    if node is None:
        return []
    if node.type in types:
        return [node]
    found: list[Node] = []
    for child in node.named_children:
        found.extend(leaves(child, types))
    return found


def by_field(types: frozenset[str], *fields: str) -> Names:
    """Names found under the named fields of a node."""

    def find(node: Node) -> list[Node]:
        found: list[Node] = []
        for name in fields:
            found.extend(leaves(node.child_by_field_name(name), types))
        return found

    return find


def first_child(types: frozenset[str], *, deep: bool = False) -> Names:
    """The first direct child (or, with ``deep``, the first leaf) of a name type."""

    def find(node: Node) -> list[Node]:
        for child in node.named_children:
            if child.type in types:
                return [child]
            if deep:
                inner = leaves(child, types)
                if inner:
                    return inner[:1]
        return []

    return find


def all_children(types: frozenset[str]) -> Names:
    """Every direct child of a name type."""

    def find(node: Node) -> list[Node]:
        return [child for child in node.named_children if child.type in types]

    return find


def no_names(node: Node) -> list[Node]:
    """A node that declares nothing."""
    return []


@dataclass(frozen=True, slots=True)
class Rules:
    """What one grammar's node types mean to the binder."""

    names: frozenset[str]
    # Node types whose leaves are names that no lookup can resolve (and the kind they carry).
    external_leaves: Mapping[str, SymbolKind] = field(default_factory=dict)
    types: Mapping[str, Names] = field(default_factory=dict)
    functions: Mapping[str, Names] = field(default_factory=dict)
    lambdas: frozenset[str] = frozenset()
    blocks: frozenset[str] = frozenset()
    # Children of a function that are its body: their statements share the function scope.
    bodies: frozenset[str] = frozenset()
    declarations: Mapping[str, tuple[Names, SymbolKind]] = field(default_factory=dict)
    # Fields (by name) of a node type that hold member names.
    members: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    # Node types whose name leaves are all external (imports, package and namespace paths).
    paths: Mapping[str, tuple[Names, SymbolKind]] = field(default_factory=dict)
    # Node types whose own name leaves are declared in the module scope (an import alias).
    aliases: Mapping[str, Names] = field(default_factory=dict)
    # An assignment declares the left-hand names of the node (dynamic languages).
    assignments: Mapping[str, Names] = field(default_factory=dict)
    # Constructor-like functions: the name is a use of the type, not a new declaration.
    constructors: frozenset[str] = frozenset()
    # Extra handlers keyed by node type, for the few shapes the table cannot express.
    custom: Mapping[str, Callable[[Node, int, "Binder"], None]] = field(default_factory=dict)
    constant_by_case: bool = True


class Binder:
    """One walk of one file."""

    def __init__(self, rules: Rules, builder: ScopeBuilder) -> None:
        self.rules = rules
        self.builder = builder
        self.stack: list[Frame] = []
        self.claimed: set[tuple[int, int]] = set()

    # --- helpers ------------------------------------------------------------------------

    def emit(self, node: Node, scope: int, role: Role, kind: SymbolKind = "variable") -> None:
        """Record one occurrence."""
        self.claimed.add((node.start_byte, node.end_byte))
        self.builder.occur(node.start_byte, node.end_byte, text_of(node), scope, role, kind)

    def push(self, nodes: Iterable[Node], scope: int) -> None:
        """Queue ``nodes`` (visited left to right) in ``scope``."""
        self.stack.extend((child, scope) for child in reversed(list(nodes)))

    def push_except(self, node: Node, skip: Iterable[Node], scope: int) -> None:
        """Queue the children of ``node`` except the ``skip`` nodes."""
        skipped = {(item.start_byte, item.end_byte) for item in skip}
        self.push(
            [c for c in node.named_children if (c.start_byte, c.end_byte) not in skipped], scope
        )

    def variable_kind(self, name: Node, scope: int, default: SymbolKind) -> SymbolKind:
        """``constant`` for an ALL_CAPS name, ``field`` inside a class body, else ``default``."""
        written = text_of(name)
        if self.rules.constant_by_case and len(written) > 1 and written.isupper():
            return "constant"
        if default == "variable" and self.builder.kind_of(scope) == "class":
            return "field"
        return default

    # --- the walk -----------------------------------------------------------------------

    def run(self, root: Node) -> None:
        """Walk the tree rooted at ``root`` once."""
        self.stack = [(root, MODULE_SCOPE)]
        while self.stack:
            node, scope = self.stack.pop()
            self.visit(node, scope)

    def visit(self, node: Node, scope: int) -> None:  # noqa: PLR0912 - one dispatch table
        """Handle one node by its type."""
        rules = self.rules
        kind = node.type
        if kind in rules.custom:
            rules.custom[kind](node, scope, self)
        elif kind in rules.types:
            self._type(node, scope)
        elif kind in rules.functions:
            self._function(node, scope)
        elif kind in rules.lambdas:
            self._lambda(node, scope)
        elif kind in rules.declarations:
            self._declaration(node, scope)
        elif kind in rules.paths:
            self._path(node, scope)
        elif kind in rules.aliases:
            self._alias(node, scope)
        elif kind in rules.assignments:
            self._assignment(node, scope)
        elif kind in rules.members:
            self._member(node, scope)
        elif kind in rules.blocks:
            self.push(node.named_children, self.builder.open("block", scope))
        elif kind in rules.external_leaves or kind in rules.names:
            if (node.start_byte, node.end_byte) in self.claimed:
                return  # a handler up the tree already recorded this name
            if kind in rules.external_leaves:
                self.emit(node, scope, "external", rules.external_leaves[kind])
            else:
                self.emit(node, scope, "reference")
        else:
            self.push(node.named_children, scope)

    def _type(self, node: Node, scope: int) -> None:
        names = self.rules.types[node.type](node)
        inner = self.builder.open("class", scope)
        for name in names:
            self.emit(name, scope, "define", "class")
        if names:
            self.builder.extent(names[0].start_byte, node.start_byte, node.end_byte)
        self.push_except(node, names, inner)

    def _function(self, node: Node, scope: int) -> None:
        names = self.rules.functions[node.type](node)
        function = self.builder.open("function", scope)
        in_class = self.builder.kind_of(scope) == "class"
        constructor = node.type in self.rules.constructors
        for name in names:
            if constructor:
                self.emit(name, scope, "reference", "class")
            else:
                self.emit(name, scope, "define", "method" if in_class else "function")
        if names:
            self.builder.extent(names[0].start_byte, node.start_byte, node.end_byte)
        skipped = {(n.start_byte, n.end_byte) for n in names}
        frames: list[Frame] = []
        for child in node.named_children:
            if (child.start_byte, child.end_byte) in skipped:
                continue
            if child.type in self.rules.bodies:
                frames.extend((inner, function) for inner in child.named_children)
            else:
                frames.append((child, function))
        self.stack.extend(reversed(frames))

    def _lambda(self, node: Node, scope: int) -> None:
        function = self.builder.open("function", scope)
        self.push(node.named_children, function)

    def _declaration(self, node: Node, scope: int) -> None:
        finder, default = self.rules.declarations[node.type]
        names = finder(node)
        for name in names:
            self.emit(name, scope, "define", self.variable_kind(name, scope, default))
        self.push_except(node, names, scope)

    def _path(self, node: Node, scope: int) -> None:
        finder, default = self.rules.paths[node.type]
        names = finder(node)
        for name in names:
            self.emit(name, scope, "external", default)
        self.push_except(node, names, scope)

    def _alias(self, node: Node, scope: int) -> None:
        names = self.rules.aliases[node.type](node)
        for name in names:
            self.emit(name, MODULE_SCOPE, "define", "import")
        self.push_except(node, names, scope)

    def _assignment(self, node: Node, scope: int) -> None:
        names = self.rules.assignments[node.type](node)
        for name in names:
            self.emit(name, scope, "define", self.variable_kind(name, scope, "variable"))
        self.push_except(node, names, scope)

    def _member(self, node: Node, scope: int) -> None:
        fields = self.rules.members[node.type]
        claimed: list[Node] = []
        for name in fields:
            claimed.extend(
                child
                for child in node.children_by_field_name(name)
                if child.type in self.rules.names
            )
        for leaf in claimed:
            self.emit(leaf, scope, "external", "field")
        self.push_except(node, claimed, scope)


def bind(root: Node, builder: ScopeBuilder, rules: Rules) -> None:
    """Feed ``builder`` the scopes and identifier occurrences of the tree rooted at ``root``."""
    Binder(rules, builder).run(root)
