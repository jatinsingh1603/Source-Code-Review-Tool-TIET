"""The symbol table: every identifier occurrence attributed to exactly one binding (E07-03).

Owning epic: E07.

``build_symbol_table(parsed, spec)`` walks the syntax tree once through the language's
``bind_scopes`` hook (``codekavach.parsing.scopes`` holds the language-neutral machinery) and
returns a ``SymbolTable``: a scope tree plus one ``Symbol`` per identifier occurrence in
``ParsedFile.identifiers()``, in source order.

**Why a reference carries the binding's scope.** The renamer asks "give me every place this
binding appears so I can rewrite them all". If a reference recorded the scope it *appears* in,
two different bindings of ``total`` in sibling functions would be indistinguishable from one
binding used twice. Recording the binding's ``scope_id`` makes ``(name, scope_id)`` a stable key
for the whole file, which is what the pseudonym generator and the vault's mapping records need
(invariants I5 and I6).

**Exactly once.** The symbols are built from the identifiers the parser captured, matched to the
binder's output by position. An identifier the binder never classified (a grammar construct the
language's rules do not cover) is not dropped: it becomes an unresolved reference
(``scope_id == -1``), which the classifier treats conservatively. ``build_symbol_table`` reports
how many such fallbacks there were to the debug log, and the corpus tests require zero.

**Unresolved is normal.** ``getattr(obj, name)``, attribute names, builtins, imported modules'
members and cross-file names have no visible binding. They are ``scope_id == -1`` rather than an
invented binding, so E09-02 can leave them alone unless every occurrence can be rewritten.

``is_definition`` is true for an occurrence that creates or re-establishes a binding in its own
scope (a parameter, an assignment target, a ``def`` or ``class`` name, an import alias) and false
for a use, including a target that ``global`` or ``nonlocal`` redirects to an outer binding.
"""

from typing import ClassVar, Final, Protocol, cast

from pydantic import Field, PrivateAttr
from tree_sitter import Node

from codekavach.core.log import get_logger
from codekavach.core.models import DataClassification, KavachModel, Location, RepoPath
from codekavach.parsing.imports import ImportRef
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.scopes import (
    UNRESOLVED,
    Binding,
    Scope,
    ScopeBuilder,
    SymbolKind,
)
from codekavach.parsing.spec import LanguageSpec

_log = get_logger("codekavach.parsing.symbols")

DEFINITION_KINDS: Final = frozenset({"function", "method", "class"})


class Symbol(KavachModel):
    """One identifier occurrence and the binding it belongs to."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    name: str
    kind: SymbolKind
    scope_id: int
    location: Location
    is_definition: bool


class DefinitionExtent(KavachModel):
    """The full range of the function, method or class that ``symbols[symbol_index]`` names."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    symbol_index: int
    location: Location


def _position(line: int, column: int | None) -> tuple[int, int]:
    return line, column if column is not None else 0


def _contains(outer: Location, inner: Location) -> bool:
    if outer.path != inner.path:
        return False
    outer_start = _position(outer.start_line, outer.start_col)
    outer_end = _position(outer.end_line, outer.end_col)
    inner_start = _position(inner.start_line, inner.start_col)
    inner_end = _position(inner.end_line, inner.end_col)
    return outer_start <= inner_start and inner_end <= outer_end


class SymbolTable(KavachModel):
    """The scopes and symbols of one file. Client data: it holds names and positions."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    scopes: tuple[Scope, ...]
    symbols: tuple[Symbol, ...]
    extents: tuple[DefinitionExtent, ...] = ()
    imports: tuple[ImportRef, ...] = ()

    _by_binding: dict[tuple[str, int], tuple[int, ...]] | None = PrivateAttr(default=None)

    def _index(self) -> dict[tuple[str, int], tuple[int, ...]]:
        if self._by_binding is None:
            grouped: dict[tuple[str, int], list[int]] = {}
            for index, symbol in enumerate(self.symbols):
                grouped.setdefault((symbol.name, symbol.scope_id), []).append(index)
            self._by_binding = {key: tuple(indices) for key, indices in grouped.items()}
        return self._by_binding

    def references(self, name: str, scope_id: int) -> tuple[Location, ...]:
        """Every occurrence bound to ``(name, scope_id)``, definition included, in source order."""
        return tuple(self.symbols[i].location for i in self._index().get((name, scope_id), ()))

    def import_origin(self, name: str, scope_id: int) -> str | None:
        """Where the import that binds ``name`` in ``scope_id`` comes from, or ``None``.

        ``internal``, ``third_party`` or ``stdlib``; ``None`` when no import binds that name there.
        """
        for ref in self.imports:
            if ref.bound == name and ref.scope_id == scope_id:
                return ref.origin
        return None

    @property
    def conservative_import_count(self) -> int:
        """How many imports are ``internal`` only because their module could not be classified."""
        return sum(1 for ref in self.imports if ref.conservative)

    def unresolved(self) -> tuple[Symbol, ...]:
        """Occurrences with no visible binding (``scope_id == -1``), in source order."""
        return tuple(symbol for symbol in self.symbols if symbol.scope_id == UNRESOLVED)

    def definitions_by_kind(self, kind: SymbolKind) -> tuple[Symbol, ...]:
        """The defining occurrences of ``kind``, in source order."""
        return tuple(s for s in self.symbols if s.is_definition and s.kind == kind)

    def enclosing(self, location: Location) -> Symbol | None:
        """The innermost function, method or class whose full range contains ``location``."""
        best: DefinitionExtent | None = None
        for extent in self.extents:
            if not _contains(extent.location, location):
                continue
            if best is None or _contains(best.location, extent.location):
                best = extent
        return None if best is None else self.symbols[best.symbol_index]


class SymbolsArtefact(KavachModel):
    """The ``symbols`` artefact of the parse stage: one table per file, and what it skipped.

    ``skipped`` maps the path of each file the stage did not analyse to a machine reason, so a
    report can say what was not covered rather than stay silent about it.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    tables: dict[RepoPath, SymbolTable]
    skipped: dict[RepoPath, str] = Field(default_factory=dict)


class ScopeBinder(Protocol):
    """The hook a language's spec provides: walk ``root`` once and feed ``builder``."""

    def __call__(self, root: Node, builder: ScopeBuilder) -> None:
        """Walk the tree rooted at ``root`` and record scopes and occurrences on ``builder``."""


def _make_symbol(
    name: str, kind: SymbolKind, scope_id: int, location: Location, is_definition: bool
) -> Symbol:
    return Symbol.model_construct(
        name=name,
        kind=kind,
        scope_id=scope_id,
        location=location,
        is_definition=is_definition,
    )


def _bind(
    parsed: ParsedFile, spec: LanguageSpec | None
) -> tuple[tuple[Scope, ...], tuple[Binding, ...], ScopeBuilder]:
    binder = cast("ScopeBinder | None", getattr(spec, "bind_scopes", None))
    builder = ScopeBuilder(
        class_body_sees_members=bool(getattr(spec, "class_body_sees_members", True)),
        class_scopes_visible=bool(getattr(spec, "class_scopes_visible", False)),
    )
    builder.open("module", None)
    if binder is not None and parsed.tree is not None:
        binder(parsed.tree.root_node, builder)
    tree, bindings = builder.build()
    return tree.scopes, bindings, builder


def _build(parsed: ParsedFile, spec: LanguageSpec | None) -> tuple[SymbolTable, int]:
    """The table and the number of identifiers the binder did not classify."""
    scopes, bindings, builder = _bind(parsed, spec)
    line_index = parsed.line_index
    # Keyed by start position: two identifiers never start at the same offset, and no ``Location``
    # is built per binding, because ``parsed.identifiers()`` already holds the real ones.
    by_start: dict[tuple[int, int], Binding] = {}
    if line_index is not None:
        position = line_index.position
        by_start = {position(binding.start): binding for binding in bindings}

    symbols: list[Symbol] = []
    unclassified = 0
    for location, text in parsed.identifiers():
        matched = by_start.get((location.start_line, location.start_col or 0))
        if matched is None:
            unclassified += 1
            symbols.append(_make_symbol(text, "variable", UNRESOLVED, location, False))
        else:
            symbols.append(
                _make_symbol(
                    matched.name, matched.kind, matched.scope_id, location, matched.is_definition
                )
            )

    extents: list[DefinitionExtent] = []
    if builder.extents and line_index is not None:
        index_by_start = {
            (symbol.location.start_line, symbol.location.start_col): index
            for index, symbol in enumerate(symbols)
        }
        full_ranges = [(e.full_start, e.full_end) for e in builder.extents]
        for extent, full in zip(
            builder.extents, line_index.locations(parsed.path, full_ranges), strict=True
        ):
            symbol_index = index_by_start.get(line_index.position(extent.name_start))
            if symbol_index is not None:
                extents.append(DefinitionExtent(symbol_index=symbol_index, location=full))
    table = SymbolTable(scopes=scopes, symbols=tuple(symbols), extents=tuple(extents))
    return table, unclassified


def build_symbol_table(parsed: ParsedFile, spec: LanguageSpec | None) -> SymbolTable:
    """Attribute every identifier of ``parsed`` to one binding.

    A file with no syntax tree (a timed-out parse), or a language whose spec has no
    ``bind_scopes`` hook, gets a table in which every identifier is an unresolved reference: the
    conservative answer, never an invented binding.
    """
    table, unclassified = _build(parsed, spec)
    if unclassified:
        _log.debug("symbols_unclassified_identifiers", path=parsed.path, count=unclassified)
    return table


def count_unclassified(parsed: ParsedFile, spec: LanguageSpec | None) -> int:
    """How many identifiers of ``parsed`` the binder did not classify (the corpus tests need 0)."""
    return _build(parsed, spec)[1]


__all__ = [
    "DEFINITION_KINDS",
    "DefinitionExtent",
    "ScopeBinder",
    "Symbol",
    "SymbolTable",
    "SymbolsArtefact",
    "build_symbol_table",
    "count_unclassified",
]
