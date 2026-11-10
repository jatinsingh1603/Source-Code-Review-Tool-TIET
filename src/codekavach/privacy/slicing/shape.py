"""Reading the structure of a parsed file: statements, containers and what must stay together.

Owning epic: E11.

The slicer needs a handful of structural facts that the symbol table does not carry: which lines
make up the statement around a location, which classes and functions enclose it, where a block
opens and closes, and which compound statements must be kept whole because cutting them would
leave code that does not parse (a ``try`` without its ``except``, a ``switch`` without its cases,
an ``else`` without its ``if``). All of it is read from the tree-sitter tree of the file, in lines
(1-based, inclusive) because slices are made of whole lines.

Only Python, JavaScript and TypeScript are described here. For any other language the slicer
refuses (``unsupported_language``) rather than guess.
"""

from dataclasses import dataclass
from typing import Final

from tree_sitter import Node

from codekavach.core.models import Language
from codekavach.parsing.functions import FunctionRange
from codekavach.parsing.models import ParsedFile

LIST_TYPES: Final = frozenset({"module", "block", "program", "statement_block", "class_body"})
FUNCTION_TYPES: Final = frozenset(
    {
        "function_definition",
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "function",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)
CLASS_TYPES: Final = frozenset(
    {"class_definition", "class_declaration", "abstract_class_declaration", "class"}
)
# Parts of a compound statement that cannot stand without the statement they belong to.
CLAUSE_TYPES: Final = frozenset(
    {
        "else_clause",
        "elif_clause",
        "except_clause",
        "except_group_clause",
        "finally_clause",
        "case_clause",
        "catch_clause",
        "switch_case",
        "switch_default",
    }
)
# Compound statements that are kept whole when the candidate sits inside one of their parts.
WHOLE_TYPES: Final = frozenset(
    {"try_statement", "try_star_statement", "match_statement", "switch_statement"}
)
IMPORT_TYPES: Final = frozenset(
    {
        "import_statement",
        "import_from_statement",
        "future_import_statement",
        "lexical_declaration",
        "variable_declaration",
        "expression_statement",
    }
)
BRACE_LANGUAGES: Final = frozenset({Language.JAVASCRIPT, Language.TYPESCRIPT})
SUPPORTED: Final = frozenset({Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT})


def first(node: Node) -> int:
    """The 1-based line a node starts on."""
    return int(node.start_point[0]) + 1


def last(node: Node) -> int:
    """The 1-based line a node ends on."""
    end_row, end_col = node.end_point
    # A node that ends at column 0 ends on the previous line (a block that swallowed the newline).
    return int(end_row) + (1 if end_col > 0 else 0)


@dataclass(frozen=True, slots=True)
class Lines:
    """An inclusive, 1-based range of whole lines."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 1 or self.end < self.start:
            raise ValueError("a line range is 1-based and not empty")

    def contains(self, line: int) -> bool:
        """Whether ``line`` is inside the range."""
        return self.start <= line <= self.end


def span(node: Node) -> Lines:
    """The lines of ``node``."""
    return Lines(first(node), max(first(node), last(node)))


def node_for_lines(parsed: ParsedFile, start: int, end: int) -> Node | None:
    """The smallest node that covers the text of lines ``start`` to ``end``, or ``None``."""
    if parsed.tree is None:
        return None
    root = parsed.tree.root_node
    lines = (root.text or b"").split(b"\n")
    if not 1 <= start <= end <= len(lines):
        return None
    first_text = lines[start - 1]
    begin = len(first_text) - len(first_text.lstrip())
    stop = len(lines[end - 1].rstrip())
    if start == end and stop <= begin:
        return None
    return root.descendant_for_point_range((start - 1, begin), (end - 1, max(stop, 0)))


def statement_of(node: Node | None) -> Node | None:
    """The statement around ``node``: the nearest ancestor-or-self that sits in a statement list.

    ``None`` when ``node`` is itself a statement list, or has no statement around it.
    """
    current = node
    while current is not None:
        parent = current.parent
        if parent is None:
            return None
        if parent.type in LIST_TYPES:
            return None if current.type in LIST_TYPES else current
        current = parent
    return None


def is_function_of(node: Node, start: int, header_start: int, end: int) -> bool:
    """Whether ``node`` is the function whose full range is ``start..end``."""
    return (
        node.type in FUNCTION_TYPES and start <= first(node) <= header_start and last(node) == end
    )


def function_node(file: ParsedFile, function: FunctionRange) -> Node | None:
    """The tree node of ``function`` (the definition itself, without its decorators).

    The smallest node covering the lines is usually the function or something inside it, so the
    search climbs; for ``export function f`` it is the export statement around the function, so
    the search then descends.
    """
    start, header, end = (
        function.full.start_line,
        function.header.start_line,
        function.full.end_line,
    )
    found = node_for_lines(file, start, end)
    node = found
    while node is not None and not is_function_of(node, start, header, end):
        node = node.parent
    if node is not None or found is None:
        return node
    stack = [found]
    while stack:
        current = stack.pop()
        if is_function_of(current, start, header, end):
            return current
        stack.extend(
            child
            for child in reversed(current.children)
            if first(child) <= end and last(child) >= start
        )
    return None


def body_of(node: Node) -> Node | None:
    """The body of a function, class or compound statement."""
    return node.child_by_field_name("body")


def header_lines(owner: Node, block: Node, language: Language) -> Lines:
    """The lines that open ``owner`` before ``block``: its header and, with braces, the ``{``."""
    start = first(owner)
    if owner.parent is not None and owner.parent.type == "decorated_definition":
        start = first(owner.parent)
    end = first(block) if language in BRACE_LANGUAGES else first(block) - 1
    return Lines(start, max(start, end))


def closer_line(block: Node, language: Language) -> Lines | None:
    """The line that closes a braced block, or ``None`` for an indentation-based language."""
    if language not in BRACE_LANGUAGES:
        return None
    line = last(block)
    return Lines(line, line)


def unit_of(statement: Node) -> Node:
    """The member of the top-level statement list that holds ``statement``.

    The list is the file's own, or the body of a class. A window of code outside any function is
    cut from the members of that list, so an ``if`` at module level is taken whole.
    """
    current = statement
    while True:
        parent = current.parent
        if parent is None:
            return current
        if parent.type in {"module", "program"}:
            return current
        if (
            parent.type in LIST_TYPES
            and parent.parent is not None
            and parent.parent.type in CLASS_TYPES
        ):
            return current
        current = parent


def _add(keep: set[int], node: Node) -> None:
    keep.update(range(first(node), max(first(node), last(node)) + 1))


def _step(  # noqa: PLR0911 - one return per structural case
    node: Node, unit: Node, language: Language, signature: Lines | None, keep: set[int]
) -> Node | None:
    """One move from ``node`` towards ``unit``, keeping what the move passes; ``None`` stops."""
    parent = node.parent
    if parent is None:
        return None
    if parent.type not in LIST_TYPES:
        if node.type in CLAUSE_TYPES or parent.type in WHOLE_TYPES:
            _add(keep, parent)
        return parent
    owner = parent.parent
    if owner is None:
        return None
    if owner == unit and signature is not None:
        closing = closer_line(parent, language)
        if closing is not None:
            keep.add(closing.start)
        return None
    if owner.type in CLAUSE_TYPES:
        # The clause's own lines now; the next step keeps the whole statement it belongs to.
        _add(keep, owner)
        return owner
    if owner.type in WHOLE_TYPES:
        _add(keep, owner)
        return owner
    opening = header_lines(owner, parent, language)
    keep.update(range(opening.start, opening.end + 1))
    closing = closer_line(parent, language)
    if closing is not None:
        keep.add(closing.start)
    return owner


def kept_lines(
    unit: Node, statement: Node, language: Language, *, signature: Lines | None
) -> set[int]:
    """Lines of ``unit`` that must survive when its interior is elided around ``statement``.

    Always kept: the lines of ``statement`` (the candidate's own), the unit's signature (for a
    function), and for every compound statement between the two the lines that open it and, in
    brace languages, the line that closes it (a guard that dominates the candidate is exactly the
    context whose absence makes a false positive). A compound statement that the candidate sits in
    a later part of, or that cannot be cut (``try``, ``match``, ``switch``), is kept whole.
    """
    keep: set[int] = set()
    _add(keep, statement)
    if signature is not None:
        keep.update(range(signature.start, signature.end + 1))
    node: Node | None = statement
    while node is not None and node != unit:
        node = _step(node, unit, language, signature, keep)
    return keep


def runs(lines: set[int]) -> list[Lines]:
    """Maximal runs of consecutive line numbers, in order."""
    ordered = sorted(lines)
    result: list[Lines] = []
    for number in ordered:
        if result and number == result[-1].end + 1:
            result[-1] = Lines(result[-1].start, number)
        else:
            result.append(Lines(number, number))
    return result
