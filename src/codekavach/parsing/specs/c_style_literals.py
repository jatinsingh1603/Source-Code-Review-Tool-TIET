"""String-literal context shared by the C-family specs (E07-05).

Owning epic: E07.

The Java and Go specs both classify a string by what builds it: the arguments of a call
(``stmt.executeQuery("...")``), the right-hand side of an assignment, and the pieces of a ``+``
chain. The grammar's node-type names differ, so a small ``Shapes`` record names them and one
function does the walk; the Python and JavaScript specs keep their own, longer variants.
"""

from dataclasses import dataclass

from tree_sitter import Node as TSNode

from codekavach.parsing.literals import LiteralContext


@dataclass(frozen=True, slots=True)
class Shapes:
    """The node types of one grammar that the context walk needs."""

    literals: frozenset[str]
    content: frozenset[str]
    binary: str
    parenthesised: str
    call: str
    callee_field: str
    arguments: str
    assignments: frozenset[str]


def _text(node: TSNode | None) -> str | None:
    if node is None or node.text is None:
        return None
    return node.text.decode("utf-8", errors="replace")


def _is_plus(node: TSNode, shapes: Shapes) -> bool:
    if node.type != shapes.binary:
        return False
    operator = node.child_by_field_name("operator")
    return operator is not None and operator.type == "+"


def _pieces(literal: TSNode, shapes: Shapes) -> list[str]:
    return [
        text
        for child in literal.children
        if child.type in shapes.content and (text := _text(child)) is not None
    ]


def _collect(node: TSNode, shapes: Shapes, found: list[TSNode]) -> None:
    """The literals of a ``+`` chain in source order; calls and names are not entered."""
    if node.type in shapes.literals:
        found.append(node)
    elif node.type == shapes.parenthesised or _is_plus(node, shapes):
        for child in node.children:
            _collect(child, shapes, found)


def _top_of_chain(literal: TSNode, shapes: Shapes) -> TSNode:
    top = literal
    while top.parent is not None:
        parent = top.parent
        if _is_plus(parent, shapes):
            top = parent
        elif (
            parent.type == shapes.parenthesised
            and parent.parent is not None
            and _is_plus(parent.parent, shapes)
        ):
            top = parent.parent
        else:
            break
    return top


def _enclosing(start: TSNode, shapes: Shapes) -> tuple[str | None, str | None]:
    ancestor = start.parent
    while ancestor is not None and (
        ancestor.type == shapes.parenthesised or _is_plus(ancestor, shapes)
    ):
        ancestor = ancestor.parent
    if ancestor is None:
        return None, None
    if ancestor.type == shapes.arguments:
        call = ancestor.parent
        if call is not None and call.type == shapes.call:
            return _callee_text(call, shapes), None
    elif ancestor.type in shapes.assignments:
        return None, _assignment_target(ancestor)
    return None, None


def _callee_text(call: TSNode, shapes: Shapes) -> str | None:
    callee = call.child_by_field_name(shapes.callee_field)
    text = _text(callee)
    owner = call.child_by_field_name("object")
    if owner is not None and (owner_text := _text(owner)) is not None and text is not None:
        return f"{owner_text}.{text}"  # Java: the receiver and the method name are separate fields
    return text


def _assignment_target(node: TSNode) -> str | None:
    for field in ("name", "left"):
        target = node.child_by_field_name(field)
        if target is not None and target.type in ("identifier", "expression_list"):
            if target.type == "expression_list" and target.named_child_count == 1:
                target = target.named_children[0]
            if target.type == "identifier":
                return _text(target)
    return None


def literal_context(node: TSNode, shapes: Shapes) -> LiteralContext:
    """The classifier context for ``node``, a string-content node of one literal."""
    literal = (
        node.parent if node.parent is not None and node.parent.type in shapes.literals else node
    )
    top = _top_of_chain(literal, shapes)
    joined: str | None = None
    if top is not literal:
        literals: list[TSNode] = []
        _collect(top, shapes, literals)
        pieces = [piece for item in literals for piece in _pieces(item, shapes)]
        if len(pieces) >= 2:
            joined = "".join(pieces)
    callee, target = _enclosing(top, shapes)
    return LiteralContext(callee_text=callee, assignment_target=target, joined_text=joined)
