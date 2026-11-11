"""The control flow graph of a lowered function (E17-01).

Owning epic: E17. Edges come from the terminators (``Branch``, ``Loop``, ``Goto``) and from
exceptions: a block holding a ``Call`` or ``Raise`` whose ``handler`` is set has an edge to that
handler block. A ``Loop`` header has its body and exit as successors; the ``Goto`` at the end of a
body is the back edge. Iteration order is reverse post-order from the entry (block 0), which is
deterministic because block ids are assigned in source order and successors are visited in
ascending order. ``exits`` holds the blocks that leave the function (a ``Return``, or a ``Raise``
with no handler).
"""

from dataclasses import dataclass
from typing import Final

from codekavach.analysis.taint.ir import (
    Branch,
    Call,
    Goto,
    IRFunction,
    Loop,
    Raise,
    Return,
)

ENTRY: Final = 0


@dataclass(frozen=True, slots=True)
class CFG:
    """Successors, predecessors and the traversal order of one function."""

    successors: dict[int, tuple[int, ...]]
    predecessors: dict[int, tuple[int, ...]]
    order: tuple[int, ...]
    back_edges: frozenset[tuple[int, int]]
    exits: frozenset[int]

    @property
    def reachable(self) -> frozenset[int]:
        """The blocks reachable from the entry."""
        return frozenset(self.order)

    def is_loop_header(self, block: int) -> bool:
        """Whether some back edge targets ``block``."""
        return any(target == block for _, target in self.back_edges)


def build_cfg(function: IRFunction) -> CFG:
    """The graph of ``function``; a function with no blocks has an empty graph."""
    successors: dict[int, set[int]] = {block.id: set() for block in function.blocks}
    exits: set[int] = set()
    for block in function.blocks:
        out = successors[block.id]
        for stmt in block.stmts:
            if isinstance(stmt, Call | Raise) and stmt.handler is not None:
                out.add(stmt.handler)
        last = block.stmts[-1] if block.stmts else None
        if isinstance(last, Branch):
            out.update((last.then_block, last.else_block))
        elif isinstance(last, Loop):
            out.update((last.body_block, last.exit_block))
        elif isinstance(last, Goto):
            out.add(last.target)
        elif isinstance(last, Return) or (isinstance(last, Raise) and last.handler is None):
            exits.add(block.id)
    ordered = {key: tuple(sorted(value)) for key, value in successors.items()}
    order, back = _traverse(ordered)
    predecessors: dict[int, list[int]] = {key: [] for key in ordered}
    for source in order:
        for target in ordered[source]:
            predecessors[target].append(source)
    return CFG(
        successors=ordered,
        predecessors={key: tuple(sorted(value)) for key, value in predecessors.items()},
        order=order,
        back_edges=frozenset(back),
        exits=frozenset(exits & set(order)),
    )


def _traverse(
    successors: dict[int, tuple[int, ...]],
) -> tuple[tuple[int, ...], set[tuple[int, int]]]:
    """Reverse post-order from the entry, and the edges that close a cycle."""
    if ENTRY not in successors:
        return (), set()
    post: list[int] = []
    back: set[tuple[int, int]] = set()
    state: dict[int, int] = {ENTRY: 1}
    stack: list[tuple[int, int]] = [(ENTRY, 0)]
    while stack:
        node, position = stack.pop()
        children = successors[node]
        if position < len(children):
            stack.append((node, position + 1))
            child = children[position]
            seen = state.get(child, 0)
            if seen == 0:
                state[child] = 1
                stack.append((child, 0))
            elif seen == 1:
                back.add((node, child))
        else:
            state[node] = 2
            post.append(node)
    return tuple(reversed(post)), back
