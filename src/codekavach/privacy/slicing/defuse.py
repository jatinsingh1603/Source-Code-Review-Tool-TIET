"""Intraprocedural def-use chains and control dependence for the path strategies (E11-03).

Owning epic: E11.

The enclosing function is the cheapest useful slice. The graph-guided strategies keep only the
statements that matter to a candidate, which needs two facts the symbol table does not state: which
statement defines the value a statement reads, and which statements decide whether it runs.

``DefUseIndex`` answers both for one file. It is built once per file and cached on the
``ParseIndex`` (``ParseIndex.defuse_of``), and it builds the flow of a function only when a
strategy first asks about it. ``definitions_reaching(location, name)`` returns the definitions of
``name`` that can reach the statement at ``location``; ``control_ancestors(location)`` returns the
compound statements the statement sits in and the guards that exit early before it.

**The unit is a statement.** A simple statement is one unit; a compound statement (``if``, ``for``,
``while``, ``with``, ``try`` and their clauses) contributes its *header* (the condition, the loop
target, the ``as`` name), and the statements of its body are units of their own. Every answer is a
``Location`` of whole lines.

**Bindings come from the symbol table.** A use and a definition belong to one binding when they
share ``(name, scope_id)``, so shadowing and members (``req.json``) are never confused with
variables. A name with no visible binding (an import, a global, a builtin) has no chain here:
crossing into other functions belongs to the interprocedural helper, not to this module.

**Which definitions reach a use.** Straight-line code: the latest definition that is *certain* to
run before the use kills the ones before it. A definition is certain when its statement list
contains the use (a definition inside a branch is not). The definitions after that one and before
the use, in any branch, also reach. Inside a loop every definition in the loop reaches, whatever
its position, which is the loop-carried dependence; a loop target is certain only inside its own
loop, because the loop may run zero times. This is a conservative over-approximation: it may keep
a definition that cannot reach, never drop one that can (dropping would hide the cause of a
finding; keeping costs tokens).

**Control dependence is not optional.** A statement depends on every compound statement around it
and on every earlier ``if`` or ``assert`` in an enclosing statement list whose branch ends the
function or the iteration (``return``, ``raise``, ``throw``, ``continue``, ``break``): the code
after ``if not allowed: raise`` runs only when ``allowed`` holds. A slice that kept the assignments
but dropped such a guard would show a guarded sink as unguarded.

Nested functions are part of their enclosing function's text, but their bindings have their own
scope ids, so a nested definition never kills an outer one.
"""

import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Final

from tree_sitter import Node

from codekavach.core.log import get_logger
from codekavach.core.models import Language, Location
from codekavach.parsing.functions import FunctionRange
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.scopes import UNRESOLVED
from codekavach.parsing.symbols import SymbolTable
from codekavach.privacy.slicing.shape import (
    BRACE_LANGUAGES,
    CLAUSE_TYPES,
    LIST_TYPES,
    WHOLE_TYPES,
    Lines,
    closer_line,
    first,
    function_node,
    kept_lines,
    last,
    runs,
    span,
)

_LOG = get_logger("codekavach.privacy.slicing")

Key = tuple[str, int]
"""A binding: ``(name, scope_id)``."""

LOOP_TYPES: Final = frozenset(
    {"for_statement", "while_statement", "for_in_statement", "do_statement", "for_of_statement"}
)
TERMINATORS: Final = frozenset(
    {
        "return_statement",
        "raise_statement",
        "continue_statement",
        "break_statement",
        "throw_statement",
    }
)
GUARD_TYPES: Final = frozenset({"if_statement", "assert_statement"})
# ``x += 1`` and ``i++`` read and write ``x``/``i``, whatever the binder says about the target.
_AUGMENTED: Final = re.compile(r"\s*(?:(?:\*\*|//|>>>|>>|<<|&&|\|\||\?\?|[-+*/%&|^@])=|\+\+|--)")


@dataclass(frozen=True, slots=True)
class Statement:
    """One unit of analysis: a simple statement, or the header of a compound one."""

    index: int
    node: Node
    lines: Lines

    @property
    def is_compound(self) -> bool:
        """Whether ``lines`` is the header of a statement that has a body of its own."""
        return self.lines != span(self.node)


@dataclass(frozen=True, slots=True)
class _Occurrence:
    name: str
    key: Key
    line: int
    col: int
    writes: bool
    reads: bool


def _is_statement(node: Node) -> bool:
    if not node.is_named or node.type == "comment" or node.type in LIST_TYPES:
        return False
    parent = node.parent
    return node.type in CLAUSE_TYPES or (parent is not None and parent.type in LIST_TYPES)


def statement_header(node: Node, language: Language) -> Lines:
    """The lines of a simple statement, or of the part of a compound one before its body."""
    bodies = [c for c in node.children if c.type in LIST_TYPES or c.type in CLAUSE_TYPES]
    if not bodies:
        return span(node)
    body = min(bodies, key=first)
    begin = first(node)
    end = first(body) if language in BRACE_LANGUAGES else first(body) - 1
    return Lines(begin, max(begin, end))


def _branch_exits(branch: Node | None) -> bool:
    """Whether a branch (a block, or one statement) ends in a terminator."""
    if branch is None:
        return False
    if branch.type in LIST_TYPES:
        named = [c for c in branch.named_children if c.type != "comment"]
        return bool(named) and named[-1].type in TERMINATORS
    return branch.type in TERMINATORS


def _exits_early(node: Node) -> bool:
    """Whether an ``if`` has a branch that leaves the function or the iteration."""
    if node.type == "assert_statement":
        return True
    if node.type != "if_statement":
        return False
    if _branch_exits(node.child_by_field_name("consequence")):
        return True
    for child in node.children:
        if child.type == "elif_clause" and _branch_exits(child.child_by_field_name("consequence")):
            return True
        if child.type == "else_clause":
            inner = [c for c in child.named_children if c.type != "comment"]
            if inner and _branch_exits(inner[0]):
                return True
    return False


class FunctionFlow:
    """The statements, bindings and chains of one function."""

    def __init__(
        self,
        parsed: ParsedFile,
        table: SymbolTable,
        function: FunctionRange,
        node: Node,
        lines: list[str],
    ) -> None:
        self.path = parsed.path
        self.language = parsed.language
        self.function = function
        self.node = node
        self.signature = Lines(function.full.start_line, function.header.end_line)
        self._statements = self._collect(node)
        self._starts = [s.lines.start for s in self._statements]
        count = len(self._statements)
        self._occurrences: list[list[_Occurrence]] = [[] for _ in range(count)]
        self._defs: dict[Key, list[int]] = {}
        self._place(table, lines, function.full.start_line, function.full.end_line)
        self._ancestors = [self._ancestor_ids(s.node) for s in self._statements]
        self._loops = [self._loops_of(s.node) for s in self._statements]
        self._reaching: dict[tuple[int, Key], tuple[int, ...]] = {}
        self._reverse: dict[tuple[int, Key], tuple[int, ...]] | None = None

    # --- construction -----------------------------------------------------------------------

    def _collect(self, root: Node) -> list[Statement]:
        # The signature is a unit of its own: the parameters are defined there.
        found: list[Statement] = [Statement(0, root, self.signature)]
        stack = list(root.children)
        while stack:
            current = stack.pop()
            stack.extend(current.children)
            if _is_statement(current):
                found.append(Statement(0, current, statement_header(current, self.language)))
        found.sort(key=lambda s: (s.lines.start, -s.lines.end, s.node.start_byte))
        return [Statement(i, s.node, s.lines) for i, s in enumerate(found)]

    def statement_at(self, line: int) -> int | None:
        """The innermost statement unit whose lines contain ``line``, or ``None``."""
        position = bisect_right(self._starts, line) - 1
        while position >= 0:
            if self._statements[position].lines.contains(line):
                return position
            position -= 1
        return None

    def _place(self, table: SymbolTable, lines: list[str], low: int, high: int) -> None:
        for symbol in table.symbols:
            line = symbol.location.start_line
            if symbol.scope_id == UNRESOLVED or not low <= line <= high:
                continue
            if symbol.location.path != self.path:
                continue
            index = self.statement_at(line)
            if index is None:
                continue
            column = symbol.location.start_col or 1
            text = lines[line - 1] if 1 <= line <= len(lines) else ""
            after = text[column - 1 + len(symbol.name) :]
            augmented = _AUGMENTED.match(after) is not None
            writes = symbol.is_definition or augmented
            reads = (not symbol.is_definition) or augmented
            key = (symbol.name, symbol.scope_id)
            self._occurrences[index].append(
                _Occurrence(symbol.name, key, line, column, writes, reads)
            )
            if writes:
                bucket = self._defs.setdefault(key, [])
                if not bucket or bucket[-1] != index:
                    bucket.append(index)

    def _ancestor_ids(self, node: Node) -> frozenset[int]:
        ids: set[int] = set()
        current: Node | None = node
        while current is not None and current != self.node:
            ids.add(current.id)
            current = current.parent
        return frozenset(ids)

    def _loops_of(self, node: Node) -> tuple[Lines, ...]:
        loops: list[Lines] = []
        current: Node | None = node
        while current is not None and current != self.node:
            if current.type in LOOP_TYPES:
                loops.append(span(current))
            current = current.parent
        return tuple(loops)

    # --- accessors --------------------------------------------------------------------------

    @property
    def statements(self) -> tuple[Statement, ...]:
        """Every unit of the function in source order (outer before inner on one line)."""
        return tuple(self._statements)

    def reads_of(self, index: int, within: Location | None = None) -> tuple[Key, ...]:
        """The bindings read by the statement, within ``within`` when that has columns."""
        keys: dict[Key, None] = {}
        for item in self._occurrences[index]:
            if item.reads and _inside(item, within):
                keys.setdefault(item.key)
        return tuple(keys)

    def writes_of(self, index: int) -> tuple[Key, ...]:
        """The bindings the statement defines, in source order."""
        keys: dict[Key, None] = {}
        for item in self._occurrences[index]:
            if item.writes:
                keys.setdefault(item.key)
        return tuple(keys)

    def location_of(self, index: int) -> Location:
        """The whole lines of a unit as a ``Location``."""
        lines = self._statements[index].lines
        return Location(path=self.path, start_line=lines.start, end_line=lines.end)

    # --- reaching definitions ---------------------------------------------------------------

    def reaching(self, use: int, key: Key) -> tuple[int, ...]:
        """The statements whose definition of ``key`` can reach the statement ``use``."""
        cached = self._reaching.get((use, key))
        if cached is not None:
            return cached
        defs = self._defs.get(key, [])
        before = [d for d in defs if d < use]
        certain = next((d for d in reversed(before) if self._certain(d, use)), None)
        reached = {d for d in before if certain is None or d >= certain}
        for loop in self._loops[use]:
            reached.update(
                d for d in defs if loop.start <= self._statements[d].lines.start <= loop.end
            )
        result = tuple(sorted(reached))
        self._reaching[(use, key)] = result
        return result

    def _certain(self, definition: int, use: int) -> bool:
        """Whether ``definition`` is certain to have run when ``use`` runs."""
        node = self._statements[definition].node
        if node == self.node:
            return True  # a parameter is bound before any statement of the body runs
        region = node.parent if node.parent is not None and node.parent.type in LIST_TYPES else node
        if region.id not in self._ancestors[use] and region != self.node:
            return False
        if node.type in LOOP_TYPES:
            return node.id in self._ancestors[use] and use != definition
        return True

    def readers(self, definition: int, key: Key) -> tuple[int, ...]:
        """The statements that read ``key`` and that ``definition`` can reach."""
        if self._reverse is None:
            built: dict[tuple[int, Key], list[int]] = {}
            for use in range(len(self._statements)):
                for read in self.reads_of(use):
                    for d in self.reaching(use, read):
                        built.setdefault((d, read), []).append(use)
            self._reverse = {k: tuple(v) for k, v in built.items()}
        return self._reverse.get((definition, key), ())

    # --- control dependence -----------------------------------------------------------------

    def guard_lines(self, index: int) -> set[int]:
        """Whole lines of the early-exit guards that decide whether the statement runs."""
        found: set[int] = set()
        current: Node | None = self._statements[index].node
        while current is not None and current != self.node:
            parent = current.parent
            if parent is not None and parent.type in LIST_TYPES:
                for sibling in parent.named_children:
                    if sibling == current:
                        break
                    if sibling.type in GUARD_TYPES and _exits_early(sibling):
                        found.update(range(first(sibling), max(first(sibling), last(sibling)) + 1))
            current = parent
        return found

    def _function_frame(self) -> set[int]:
        """The signature and, in brace languages, the line that closes the function."""
        frame = set(range(self.signature.start, self.signature.end + 1))
        closing = closer_line_of_function(self.node, self.language)
        if closing is not None:
            frame.add(closing)
        return frame

    def _around(self, index: int) -> set[int]:
        """Lines of the compound statements around the unit and their closers, not the frame."""
        statement = self._statements[index]
        node = statement.node
        everything = set(range(first(node), max(first(node), last(node)) + 1))
        own = set(range(statement.lines.start, statement.lines.end + 1))
        around = kept_lines(self.node, node, self.language, signature=self.signature)
        return around - (everything - own) - own - self._function_frame()

    def control_lines(self, index: int) -> set[int]:
        """Lines of the compound statements around the unit, their closers and the guards."""
        return self._around(index) | self.guard_lines(index)

    def keep_lines(self, index: int, *, whole: bool = False) -> set[int]:
        """Every line needed to show the unit in place: itself, what controls it, the signature.

        ``whole`` takes a compound statement with its body, the fallback when a header alone
        does not parse.
        """
        statement = self._statements[index]
        node = statement.node
        own = set(range(statement.lines.start, statement.lines.end + 1))
        parent = node.parent
        if whole or node.type in WHOLE_TYPES or (parent is not None and parent.type in WHOLE_TYPES):
            own = set(range(first(node), max(first(node), last(node)) + 1))
        if statement.is_compound and self.language in BRACE_LANGUAGES:
            for child in node.children:
                if child.type in LIST_TYPES:
                    closing = closer_line(child, self.language)
                    if closing is not None:
                        own.add(closing.start)
        return own | self._function_frame() | self.control_lines(index)


def closer_line_of_function(node: Node, language: Language) -> int | None:
    """The line that closes the body of a function in a brace language, else ``None``."""
    body = node.child_by_field_name("body")
    if body is None:
        return None
    closing = closer_line(body, language)
    return None if closing is None else closing.start


def _inside(item: _Occurrence, within: Location | None) -> bool:
    if within is None or within.start_col is None or within.end_col is None:
        return True
    start = (within.start_line, within.start_col)
    end = (within.end_line, within.end_col)
    return start <= (item.line, item.col) <= end


class DefUseIndex:
    """The def-use flow of every function of one file, built when first asked for."""

    def __init__(
        self,
        parsed: ParsedFile,
        table: SymbolTable,
        functions: tuple[FunctionRange, ...],
    ) -> None:
        self._parsed = parsed
        self._table = table
        self._functions = functions
        self._flows: dict[int, FunctionFlow | None] = {}
        self._lines: list[str] | None = None

    def _function_at(self, location: Location) -> FunctionRange | None:
        best: FunctionRange | None = None
        for item in self._functions:
            contains = (
                item.full.start_line <= location.start_line
                and location.end_line <= item.full.end_line
            )
            if contains and (
                best is None
                or (
                    item.full.start_line >= best.full.start_line
                    and item.full.end_line <= best.full.end_line
                )
            ):
                best = item
        return best

    def flow_for(self, location: Location) -> FunctionFlow | None:
        """The flow of the innermost function around ``location``; ``None`` outside functions."""
        function = self._function_at(location)
        if function is None:
            return None
        key = function.full.start_line * 1_000_003 + function.full.end_line
        if key not in self._flows:
            node = function_node(self._parsed, function)
            if node is None:
                self._flows[key] = None
            else:
                if self._lines is None:
                    self._lines = self._parsed.source.expose().split("\n")
                self._flows[key] = FunctionFlow(
                    self._parsed, self._table, function, node, self._lines
                )
        return self._flows[key]

    def definitions_reaching(self, location: Location, name: str) -> tuple[Location, ...]:
        """The definitions of ``name`` that can reach the statement at ``location``.

        Parameters count as definitions (they sit on the signature). The result is in source
        order and empty when ``name`` has no visible binding read there.
        """
        flow = self.flow_for(location)
        if flow is None:
            return ()
        index = flow.statement_at(location.start_line)
        if index is None:
            return ()
        reached: set[int] = set()
        for key in flow.reads_of(index):
            if key[0] == name:
                reached.update(flow.reaching(index, key))
        return tuple(flow.location_of(i) for i in sorted(reached))

    def control_ancestors(self, location: Location) -> tuple[Location, ...]:
        """The compound statements around ``location`` and the guards before it (same function)."""
        flow = self.flow_for(location)
        if flow is None:
            return ()
        index = flow.statement_at(location.start_line)
        if index is None:
            return ()
        return tuple(
            Location(path=flow.path, start_line=run.start, end_line=run.end)
            for run in runs(flow.control_lines(index))
        )
