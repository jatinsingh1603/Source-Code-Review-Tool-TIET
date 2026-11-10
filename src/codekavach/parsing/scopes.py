"""Scopes, bindings and name resolution (E07-03).

Owning epic: E07.

Renaming is only safe if it is scope-correct (``docs/research/INSIGHTS.md`` section 3.3 item 9):
two bindings of ``total`` in sibling functions are two names, one binding used twice is one.
This module holds the language-neutral part of that: the ``Scope`` model, the ``ScopeTree`` that
answers ``lookup(name, from_scope)``, and the ``ScopeBuilder`` a language's binder (the
``bind_scopes`` hook of its ``LanguageSpec``) feeds while it walks the syntax tree once.

The builder is deliberately two-phase. The binder only *records*: scopes it opens, names it
declares, and every identifier occurrence with the scope it appears in and its role. Nothing is
resolved during the walk, so hoisting (a ``var`` or a function declaration used before its
declaration) and the temporal dead zone (a ``let`` is bound for its whole block) need no special
case: by the time ``build`` resolves a reference, every declaration of the file is known.

The builder takes plain integers and strings, never tree-sitter nodes, so it is testable without a
grammar and cannot hold native memory.

Resolution order, shared by Python and JavaScript/TypeScript:

* walk outwards from the scope an occurrence appears in, innermost first;
* a class scope is skipped unless it is the starting scope and the language lets a class body see
  its own members (Python does, JavaScript does not), so a method body never sees class-level names;
* ``global`` rebinds a name to the module scope and ``nonlocal`` to the nearest enclosing
  function scope that declares it (class scopes skipped).

A name with no visible binding is *unresolved*: ``scope_id == UNRESOLVED`` (-1). That is the
honest answer for builtins, imported modules' attributes, ``getattr`` and cross-file names, and it
lets the classifier (E09-02) apply a conservative default instead of an invented binding.
"""

from dataclasses import dataclass
from typing import ClassVar, Final, Literal, NamedTuple

from codekavach.core.models import DataClassification, KavachModel

ScopeKind = Literal["module", "function", "class", "block"]
SymbolKind = Literal[
    "function",
    "class",
    "method",
    "variable",
    "parameter",
    "field",
    "module",
    "constant",
    "import",
]
Role = Literal["define", "reference", "external"]

UNRESOLVED: Final = -1
MODULE_SCOPE: Final = 0


class Scope(KavachModel):
    """One lexical scope. ``id`` is its index in ``SymbolTable.scopes``; the module scope is 0."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    id: int
    parent_id: int | None
    kind: ScopeKind


class Occurrence(NamedTuple):
    """One identifier occurrence as the binder saw it, before resolution.

    ``define`` declares ``name`` in ``scope`` (a parameter, an assignment target, a ``def``).
    ``reference`` is resolved by lookup from ``scope``. ``external`` never resolves lexically
    (an attribute name, a keyword-argument name, a module path) and carries its own ``kind``.
    """

    start: int
    end: int
    name: str
    scope: int
    role: Role
    kind: SymbolKind


class Binding(NamedTuple):
    """An occurrence after resolution. ``scope_id`` is the scope of the binding, not of the use."""

    start: int
    end: int
    name: str
    kind: SymbolKind
    scope_id: int
    is_definition: bool


class Extent(NamedTuple):
    """The full source range of a function, method or class, keyed by its name's position."""

    name_start: int
    full_start: int
    full_end: int


@dataclass(frozen=True, slots=True)
class ScopeTree:
    """The finished scope structure with the names each scope declares."""

    scopes: tuple[Scope, ...]
    declared: tuple[dict[str, SymbolKind], ...]
    global_names: tuple[frozenset[str], ...]
    nonlocal_names: tuple[frozenset[str], ...]
    class_body_sees_members: bool
    class_scopes_visible: bool = False

    def _walk(self, name: str, start: int | None, *, first_is_start: bool) -> int | None:
        scope_id = start
        first = first_is_start
        while scope_id is not None:
            scope = self.scopes[scope_id]
            visible = (
                scope.kind != "class"
                or self.class_scopes_visible
                or (first and self.class_body_sees_members)
            )
            if visible and name in self.declared[scope_id]:
                return scope_id
            first = False
            scope_id = scope.parent_id
        return None

    def lookup(self, name: str, from_scope: int) -> int | None:
        """The scope ``name`` is bound in when used from ``from_scope``, or ``None``."""
        if name in self.global_names[from_scope]:
            return MODULE_SCOPE if name in self.declared[MODULE_SCOPE] else None
        if name in self.nonlocal_names[from_scope]:
            return self._walk(name, self.scopes[from_scope].parent_id, first_is_start=False)
        return self._walk(name, from_scope, first_is_start=True)


class ScopeBuilder:
    """Collects scopes and occurrences during one walk, then resolves them in ``build``."""

    def __init__(
        self, *, class_body_sees_members: bool = True, class_scopes_visible: bool = False
    ) -> None:
        self._class_body_sees_members = class_body_sees_members
        self._class_scopes_visible = class_scopes_visible
        self._kinds: list[ScopeKind] = []
        self._parents: list[int | None] = []
        self._comprehensions: set[int] = set()
        self._globals: list[set[str]] = []
        self._nonlocals: list[set[str]] = []
        self._occurrences: list[Occurrence] = []
        self._extents: list[Extent] = []

    def open(self, kind: ScopeKind, parent: int | None, *, comprehension: bool = False) -> int:
        """Open a scope below ``parent`` (``None`` only for the module scope) and return its id."""
        scope_id = len(self._kinds)
        self._kinds.append(kind)
        self._parents.append(parent)
        self._globals.append(set())
        self._nonlocals.append(set())
        if comprehension:
            self._comprehensions.add(scope_id)
        return scope_id

    def kind_of(self, scope_id: int) -> ScopeKind:
        """The kind of an opened scope."""
        return self._kinds[scope_id]

    def enclosing_function(self, scope_id: int, *, skip_comprehensions: bool = True) -> int:
        """The nearest function or module scope at or above ``scope_id``.

        Where ``var`` (JavaScript) and the walrus operator (Python) bind. A comprehension scope
        is skipped by default because it is a function scope only for its own loop variables.
        """
        current: int | None = scope_id
        while current is not None:
            is_comprehension = skip_comprehensions and current in self._comprehensions
            if self._kinds[current] in ("function", "module") and not is_comprehension:
                return current
            current = self._parents[current]
        return MODULE_SCOPE

    def declare_global(self, scope_id: int, name: str) -> None:
        """Make ``name`` refer to the module scope inside ``scope_id`` (Python ``global``)."""
        self._globals[scope_id].add(name)

    def declare_nonlocal(self, scope_id: int, name: str) -> None:
        """Make ``name`` refer to an enclosing function scope (Python ``nonlocal``)."""
        self._nonlocals[scope_id].add(name)

    def occur(  # noqa: PLR0917 - mirrors the Occurrence record it appends
        self,
        start: int,
        end: int,
        name: str,
        scope_id: int,
        role: Role,
        kind: SymbolKind = "variable",
    ) -> None:
        """Record one identifier occurrence at the byte span ``[start, end)``."""
        self._occurrences.append(Occurrence(start, end, name, scope_id, role, kind))

    def extent(self, name_start: int, full_start: int, full_end: int) -> None:
        """Record the full range of the function or class whose name begins at ``name_start``."""
        self._extents.append(Extent(name_start, full_start, full_end))

    @property
    def extents(self) -> tuple[Extent, ...]:
        """The recorded definition extents."""
        return tuple(self._extents)

    def build(self) -> tuple[ScopeTree, tuple[Binding, ...]]:
        """Resolve every occurrence; the bindings come back in source order."""
        declared: list[dict[str, SymbolKind]] = [{} for _ in self._kinds]
        tree = ScopeTree(
            scopes=tuple(
                Scope(id=index, parent_id=parent, kind=kind)
                for index, (kind, parent) in enumerate(zip(self._kinds, self._parents, strict=True))
            ),
            declared=tuple(declared),
            global_names=tuple(frozenset(names) for names in self._globals),
            nonlocal_names=tuple(frozenset(names) for names in self._nonlocals),
            class_body_sees_members=self._class_body_sees_members,
            class_scopes_visible=self._class_scopes_visible,
        )
        ordered = sorted(self._occurrences, key=lambda occurrence: occurrence.start)
        redirected: list[Occurrence] = []
        for occurrence in ordered:
            if occurrence.role != "define":
                continue
            names_global = tree.global_names[occurrence.scope]
            names_nonlocal = tree.nonlocal_names[occurrence.scope]
            if occurrence.name in names_global or occurrence.name in names_nonlocal:
                redirected.append(occurrence)
            else:
                declared[occurrence.scope].setdefault(occurrence.name, occurrence.kind)
        for occurrence in redirected:
            if occurrence.name in tree.global_names[occurrence.scope]:
                declared[MODULE_SCOPE].setdefault(occurrence.name, occurrence.kind)
        bindings = tuple(self._resolve(tree, occurrence) for occurrence in ordered)
        return tree, bindings

    @staticmethod
    def _resolve(tree: ScopeTree, occurrence: Occurrence) -> Binding:
        if occurrence.role == "external":
            return Binding(
                occurrence.start,
                occurrence.end,
                occurrence.name,
                occurrence.kind,
                UNRESOLVED,
                False,
            )
        redirected = (
            occurrence.name in tree.global_names[occurrence.scope]
            or occurrence.name in tree.nonlocal_names[occurrence.scope]
        )
        if occurrence.role == "define" and not redirected:
            # A definition binds where it is made: no lookup, so a class scope that lookups skip
            # still holds its own members.
            kind = tree.declared[occurrence.scope][occurrence.name]
            return Binding(
                occurrence.start, occurrence.end, occurrence.name, kind, occurrence.scope, True
            )
        found = tree.lookup(occurrence.name, occurrence.scope)
        if found is None:
            return Binding(
                occurrence.start, occurrence.end, occurrence.name, "variable", UNRESOLVED, False
            )
        kind = tree.declared[found][occurrence.name]
        return Binding(occurrence.start, occurrence.end, occurrence.name, kind, found, False)
