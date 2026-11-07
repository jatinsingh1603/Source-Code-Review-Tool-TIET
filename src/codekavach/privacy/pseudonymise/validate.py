"""Proof that a pseudonymised text has the shape of the text it came from (E09-05).

Owning epic: E09.

``ast_signature`` is the pre-order sequence of node types of a parse tree, anonymous nodes
(punctuation and keywords) included, comments left out, and no leaf text and no position in it.
``assert_ast_isomorphic`` parses both texts and compares the two sequences.

What the check catches: an edit that broke the syntax, one that merged two tokens, a blanked
docstring that left an empty statement, a shaper that dropped a closing quote. What it does not
catch: a rename that is valid but wrong, such as two distinct bindings given one token. That is
the job of the classifier and the renamer, and of their property tests; the check is a net under
them and not a proof of correctness.

Comments are left out of the sequence because the pseudonymiser removes them by design. A
shorthand property that the renamer expanded (``{ a }`` to ``{ a: var_1 }``) is written as the
pair it became: the caller passes the start offsets of the expanded nodes in the original.

An ``ERROR`` or ``MISSING`` node is a failure when the output has more of them than the input.
When both have the same ones in the same places, the sequences are equal and the check passes,
because the input may legitimately not parse cleanly.

A failure message carries node types and indices only, never source text.
"""

from collections.abc import Collection
from dataclasses import dataclass
from typing import Final

from tree_sitter import Node
from tree_sitter import Parser as TSParser

from codekavach.core.models import RawCode
from codekavach.parsing.loader import load_language
from codekavach.parsing.spec import LanguageSpec
from codekavach.privacy.errors import PseudonymError

Entry = tuple[str, str]
"""A node type and the type of the node that encloses it."""

_ROOT: Final = "<root>"
_END: Final = "<end>"
_ERROR: Final = "ERROR"
_MISSING: Final = "MISSING"
_EXPANDED_PAIR: Final = {
    "shorthand_property_identifier": ("pair", "property_identifier", ":", "identifier"),
    "shorthand_property_identifier_pattern": (
        "pair_pattern",
        "property_identifier",
        ":",
        "identifier",
    ),
}
_EXPANDED_DEFAULT: Final = (
    "pair_pattern",
    "property_identifier",
    ":",
    "assignment_pattern",
    "identifier",
)


@dataclass(frozen=True, slots=True)
class Signature:
    """The node types of one tree, kept to compare many outputs against one input.

    ``types`` is the sequence; ``root`` and ``expanded`` let the slow path rebuild the sequence
    with the enclosing node of each entry when a difference has to be described.
    """

    types: list[str]
    has_error: bool
    root: Node
    expanded: frozenset[int]


def _label(node: Node) -> str:
    if node.is_missing:
        return f"{_MISSING}:{node.type}"
    return _ERROR if node.type == _ERROR else node.type


def _entries(root: Node, expanded: Collection[int]) -> list[Entry]:
    """The sequence with the enclosing node type of each entry; the slow, descriptive path."""
    out: list[Entry] = []
    stack: list[tuple[Node | Entry, str]] = [(root, _ROOT)]
    while stack:
        item, parent = stack.pop()
        if isinstance(item, tuple):
            out.append(item)
            continue
        kind = item.type
        if kind == "comment":
            continue
        if expanded and item.start_byte in expanded and kind in _EXPANDED_PAIR:
            out.extend((name, kind) for name in _EXPANDED_PAIR[kind])
            continue
        children = item.children
        if (
            expanded
            and kind == "object_assignment_pattern"
            and children
            and children[0].start_byte in expanded
        ):
            # ``{ a = 1 }`` became ``{ a: var_1 = 1 }``: a pair whose value has the default.
            out.extend((name, kind) for name in _EXPANDED_DEFAULT)
            stack.extend((child, "assignment_pattern") for child in reversed(children[1:]))
            continue
        label = _label(item)
        out.append((label, parent))
        stack.extend((child, label) for child in reversed(children))
    return out


def _types(root: Node, expanded: frozenset[int]) -> list[str]:
    """The node types of a tree that has no error node, in pre-order, by a cursor walk."""
    out: list[str] = []
    append = out.append
    skip: set[int] = set()
    cursor = root.walk()
    while True:
        node = cursor.node
        assert node is not None  # noqa: S101 - a cursor on a tree always has a node
        kind = node.type
        descend = True
        if kind == "comment" or (skip and node.start_byte in skip):
            descend = False
        elif expanded and node.start_byte in expanded and kind in _EXPANDED_PAIR:
            out.extend(_EXPANDED_PAIR[kind])
            descend = False
        elif expanded and kind == "object_assignment_pattern":
            first = node.child(0)
            if first is not None and first.start_byte in expanded:
                out.extend(_EXPANDED_DEFAULT)
                skip.add(first.start_byte)
            else:
                append(kind)
        else:
            append(kind)
        if descend and cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return out


def _tree_root(text: str, spec: LanguageSpec) -> Node:
    """A bare parse: no identifier, literal or comment extraction."""
    tree = TSParser(load_language(spec.language)).parse(text.encode("utf-8"))
    if tree is None:
        raise PseudonymError("the text could not be parsed")
    return tree.root_node


def signature_of(root: Node, *, expanded: Collection[int] = ()) -> Signature:
    """The signature of the tree under ``root``; ``expanded`` as in ``assert_ast_isomorphic``."""
    marked = frozenset(expanded)
    if root.has_error:
        types = [kind for kind, _ in _entries(root, marked)]
        return Signature(types, True, root, marked)
    return Signature(_types(root, marked), False, root, marked)


def ast_signature(
    text: str, spec: LanguageSpec, *, expanded: Collection[int] = ()
) -> tuple[str, ...]:
    """The pre-order node types of ``text``: anonymous nodes in, comments and leaf text out."""
    return tuple(signature_of(_tree_root(text, spec), expanded=expanded).types)


def _faulty(entries: list[Entry]) -> int:
    return sum(1 for kind, _ in entries if kind.startswith((_ERROR, _MISSING)))


def check_against(original: Signature, pseudonymised: str, spec: LanguageSpec) -> None:
    """Compare ``pseudonymised`` with the signature of its original; see the module docstring.

    Raises:
        PseudonymError: the sequences differ. The message has the index of the first difference,
            the two node types and the type of the enclosing node, and no source text.
    """
    output = signature_of(_tree_root(pseudonymised, spec))
    if not original.has_error and not output.has_error and output.types == original.types:
        return
    before = _entries(original.root, original.expanded)
    after = _entries(output.root, frozenset())
    extra = _faulty(after) - _faulty(before)
    if extra > 0:
        raise PseudonymError(
            f"the pseudonymised text has {extra} syntax error node(s) that the original has not"
        )
    if [kind for kind, _ in after] == [kind for kind, _ in before]:
        return
    for index in range(max(len(before), len(after))):
        was = before[index] if index < len(before) else (_END, _END)
        now = after[index] if index < len(after) else (_END, _END)
        if was[0] != now[0]:
            raise PseudonymError(
                "the pseudonymised text is not isomorphic to the original: first difference at "
                f"node {index} (original {was[0]!r}, output {now[0]!r}) inside "
                f"{now[1] if now[0] != _END else was[1]!r}; "
                f"{len(before)} nodes before, {len(after)} after"
            )
    raise PseudonymError("the pseudonymised text is not isomorphic to the original")


def assert_ast_isomorphic(
    original: RawCode,
    pseudonymised: str,
    spec: LanguageSpec,
    *,
    expanded: Collection[int] = (),
) -> None:
    """Raise unless ``pseudonymised`` has the node-type sequence of ``original``.

    ``expanded`` holds the start offsets, in ``original``, of the shorthand properties the
    renamer expanded into pairs.

    Raises:
        PseudonymError: the two sequences differ; see ``check_against`` for the message.
    """
    before = signature_of(_tree_root(original.expose(), spec), expanded=expanded)
    check_against(before, pseudonymised, spec)
