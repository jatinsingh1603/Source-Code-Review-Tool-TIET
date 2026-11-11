"""What the language lowerings share: the context, the block builder and small helpers (E17-01).

Owning epic: E17. A lowering walks a tree-sitter tree and drives a ``FunctionBuilder`` that
numbers blocks in source order, hoists nested calls into temporaries so every ``Call`` is its own
statement, and enforces the node, block and time caps. It does not fold constants, drop dead code,
reorder anything or resolve names beyond the symbol table: when in doubt it emits ``Unknown``.
"""

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Final

from tree_sitter import Node

from codekavach.analysis.taint.ir import (
    ANY_INDEX,
    MAX_SHAPE,
    TERMINATORS,
    CalleeRef,
    Const,
    Expr,
    Goto,
    IRBlock,
    Place,
    Return,
    Stmt,
    Unknown,
)
from codekavach.config.models.taint import TaintSettings
from codekavach.core.models import Language, Location
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.symbols import SymbolTable

CLOCK_EVERY: Final = 256
MAX_TEXT: Final = 512


class Skip(Exception):  # noqa: N818 - control flow, not an error condition
    """A function is too big or took too long: it is recorded as skipped, with ``reason``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def aliases_of(symbols: SymbolTable) -> dict[str, str]:
    """Local name to qualified dotted name, from the symbol table's imports."""
    found: dict[str, str] = {}
    for ref in symbols.imports:
        if not ref.bound:
            continue
        module = ref.module.removeprefix("node:")
        member = ref.imported
        found[ref.bound] = module if member in (None, "*") else f"{module}.{member}"
    return found


@dataclass(slots=True)
class Context:
    """Per-file state: where nodes are, how names resolve and how much work is allowed."""

    parsed: ParsedFile
    symbols: SymbolTable
    settings: TaintSettings
    language: Language
    aliases: dict[str, str] = field(default_factory=dict)
    deadline: float = 0.0
    _locations: dict[tuple[int, int], Location] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.aliases = aliases_of(self.symbols)
        self.deadline = time.monotonic() + self.settings.timeout_seconds

    def loc(self, node: Node) -> Location:
        """The location of ``node``; built without re-validating a path the parser checked."""
        key = (node.start_byte, node.end_byte)
        found = self._locations.get(key)
        if found is None:
            index = self.parsed.line_index
            assert index is not None  # noqa: S101 - a parsed tree always has its line index
            start_line, start_col = index.position(node.start_byte)
            end_line, end_col = index.position(node.end_byte)
            found = Location.model_construct(
                path=self.parsed.path,
                start_line=start_line,
                end_line=end_line,
                start_col=start_col,
                end_col=end_col,
                symbol=None,
            )
            self._locations[key] = found
        return found

    @staticmethod
    def text(node: Node | None) -> str:
        """The source text of ``node``."""
        return "" if node is None or node.text is None else node.text.decode("utf-8", "replace")

    def callee(self, node: Node | None, text: str | None = None) -> CalleeRef:
        """A callee reference: its text and, when its head is imported, the dotted symbol."""
        raw = (text if text is not None else self.text(node))[:MAX_TEXT]
        head, dot, rest = raw.partition(".")
        target = self.aliases.get(head)
        symbol = None if target is None else target + (dot + rest if dot else "")
        return CalleeRef(text=raw, symbol=symbol)

    def shape(self, literal: str) -> str:
        """The part of a string literal kept as its shape."""
        return literal[:MAX_SHAPE]


def mentions_of(
    node: Node, ctx: Context, identifier_types: frozenset[str], limit: int = 64
) -> tuple[Place, ...]:
    """The distinct bare names a node mentions, in source order (for ``Unknown``)."""
    seen: dict[str, None] = {}
    stack = [node]
    while stack and len(seen) < limit:
        current = stack.pop()
        if current.type in identifier_types:
            seen.setdefault(ctx.text(current), None)
        else:
            stack.extend(reversed(current.children))
    return tuple(Place(base=name) for name in seen if name)


class FunctionBuilder:
    """Collects the blocks of one function; ids are handed out in source order."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.blocks: list[list[Stmt]] = [[]]
        self.closed: set[int] = set()
        self.current = 0
        self.handlers: list[int] = []
        self.loops: list[tuple[int, int]] = []
        self.nodes = 0
        self._temps = 0

    # --- budget ------------------------------------------------------------------------------

    def tick(self, amount: int = 1) -> None:
        """Count ``amount`` nodes; raise ``Skip`` past the node cap or the deadline."""
        before = self.nodes
        self.nodes += amount
        if self.nodes > self.ctx.settings.max_function_nodes:
            raise Skip("max_function_nodes")
        if (
            self.nodes // CLOCK_EVERY != before // CLOCK_EVERY
            and time.monotonic() > self.ctx.deadline
        ):
            raise Skip("timeout")

    # --- blocks ------------------------------------------------------------------------------

    def new_block(self) -> int:
        """A fresh empty block; its id is the next number."""
        if len(self.blocks) >= self.ctx.settings.max_blocks:
            raise Skip("max_blocks")
        self.blocks.append([])
        return len(self.blocks) - 1

    def switch(self, block: int) -> None:
        """Continue emitting into ``block``."""
        self.current = block

    @property
    def handler(self) -> int | None:
        """The innermost ``try`` dispatch block, if emitting inside one."""
        return self.handlers[-1] if self.handlers else None

    def emit(self, stmt: Stmt) -> None:
        """Append ``stmt``; a closed block is replaced by a fresh unreachable one first."""
        self.tick()
        if self.current in self.closed:
            self.current = self.new_block()
        self.blocks[self.current].append(stmt)
        if isinstance(stmt, TERMINATORS):
            self.closed.add(self.current)

    def goto(self, target: int) -> None:
        """Jump to ``target`` unless the block already ends."""
        if self.current not in self.closed:
            self.emit(Goto(target=target))

    def temp(self) -> Place:
        """A fresh compiler temporary."""
        self._temps += 1
        return Place(base=f"$t{self._temps}")

    def finish(self, anchor: Node) -> tuple[IRBlock, ...]:
        """Close the open block with an implicit return and freeze the blocks."""
        if self.current not in self.closed:
            self.emit(Return(implicit=True, location=self.ctx.loc(anchor)))
        for index, stmts in enumerate(self.blocks):
            if not stmts or not isinstance(stmts[-1], TERMINATORS):
                self.blocks[index] = [*stmts, Return(implicit=True)]
        return tuple(IRBlock(id=i, stmts=tuple(s)) for i, s in enumerate(self.blocks))


def walk(node: Node) -> Iterator[Node]:
    """Every node of the subtree, parents first."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def has_error(node: Node) -> bool:
    """Whether the subtree holds a syntax error."""
    return node.has_error


def const_of(kind: str, shape: str | None = None) -> Const:
    """A literal of ``kind`` (``str``, ``int``, ``bool``, ``none``, ``regex`` or ``other``)."""
    return Const(kind=kind, shape=shape)  # type: ignore[arg-type]


def unknown(node: Node, ctx: Context, identifier_types: frozenset[str], reason: str) -> Unknown:
    """The conservative node for a construct this lowering does not express."""
    return Unknown(
        mentions=mentions_of(node, ctx, identifier_types), reason=reason, location=ctx.loc(node)
    )


def is_place(value: Expr) -> bool:
    """Whether ``value`` is a ``Place``."""
    return isinstance(value, Place)


def with_step(place: Place, step: str, ctx: Context) -> Place:
    """``place`` extended by one step, cut at ``taint.max_access_path``."""
    return place.extend(step, ctx.settings.max_access_path)


def any_index(place: Place, ctx: Context) -> Place:
    """``place[*]``."""
    return with_step(place, ANY_INDEX, ctx)
