"""Exact source ranges of every named function and method (E07-03).

Owning epic: E07.

``function_ranges(parsed, spec)`` lets the slicer (E11-01) cut an enclosing function without
guessing where it starts. Each ``FunctionRange`` carries three ranges that nest:

* ``full``: the whole definition, **including** its decorators (Python ``@decorator`` lines, the
  decorators written before a TypeScript method).
* ``header``: from the first token after the decorators to the last token before the body, so
  the ``def`` or ``function`` keyword, the name, the parameters, the return annotation and the
  ``:`` or ``=>`` that introduces the body.
* ``body``: the suite, block or expression the function evaluates.

``decorators`` lists each decorator's own range. Python's ``decorated_definition`` wraps the
function in the grammar, so ``full`` is that wrapper; in TypeScript the decorators are siblings
written just before the method, so ``full`` starts at the first of them.

Only functions with a name are listed. An arrow function or function expression is named by what
it is bound to (``const f = () => 1``, ``obj.run = function () {}``, a class field); an anonymous
callback is not a function the slicer can ask for by name, so it is skipped, though functions
nested inside it are still found. ``qualified_name`` joins the enclosing class and function names
with dots (``Account.deposit``, ``outer.inner``).

One pass over the tree with an explicit stack; ranges are converted to ``Location`` in one bulk
call so the cost stays a fraction of the parse.
"""

from dataclasses import dataclass
from typing import ClassVar, Final, Literal

from tree_sitter import Node

from codekavach.core.models import DataClassification, KavachModel, Language, Location
from codekavach.parsing.models import ParsedFile
from codekavach.parsing.spec import LanguageSpec

FunctionKind = Literal["function", "method"]

_PYTHON_SCOPES: Final = frozenset({"function_definition", "class_definition"})
_JS_FUNCTION_DECLARATIONS: Final = frozenset(
    {"function_declaration", "generator_function_declaration"}
)
_JS_FUNCTION_VALUES: Final = frozenset(
    {"arrow_function", "function_expression", "function", "generator_function"}
)
_JS_CLASSES: Final = frozenset({"class_declaration", "abstract_class_declaration", "class"})
_JS_FIELDS: Final = frozenset({"field_definition", "public_field_definition"})


class FunctionRange(KavachModel):
    """The ranges of one function or method definition (client data: names and positions)."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    symbol_name: str
    qualified_name: str
    kind: FunctionKind
    header: Location
    body: Location
    full: Location
    decorators: tuple[Location, ...] = ()


@dataclass(frozen=True, slots=True)
class _Raw:
    """A function found by a walker, still as byte offsets."""

    name: str
    qualified: str
    kind: FunctionKind
    header_start: int
    header_end: int
    body: tuple[int, int]
    full: tuple[int, int]
    decorators: list[tuple[int, int]]


def _text(node: Node | None) -> str:
    return "" if node is None else (node.text or b"").decode("utf-8", errors="replace")


def _header_end(body: Node) -> int:
    """Where the header ends: after the last token before the body (``:``, ``)``, ``=>``)."""
    lead = body.prev_sibling
    return lead.end_byte if lead is not None else body.start_byte


def _qualify(prefix: str, name: str) -> str:
    return f"{prefix}.{name}" if prefix else name


def _python_functions(root: Node) -> list[_Raw]:
    found: list[_Raw] = []
    # node, qualified prefix, whether the nearest enclosing definition is a class
    stack: list[tuple[Node, str, bool]] = [(root, "", False)]
    while stack:
        node, prefix, in_class = stack.pop()
        if node.type not in _PYTHON_SCOPES:
            stack.extend((child, prefix, in_class) for child in reversed(node.named_children))
            continue
        name_node = node.child_by_field_name("name")
        body = node.child_by_field_name("body")
        name = _text(name_node)
        qualified = _qualify(prefix, name)
        if node.type == "function_definition" and body is not None and name:
            parent = node.parent
            wrapper = (
                parent if parent is not None and parent.type == "decorated_definition" else node
            )
            decorators = [
                (child.start_byte, child.end_byte)
                for child in wrapper.named_children
                if child.type == "decorator"
            ]
            found.append(
                _Raw(
                    name=name,
                    qualified=qualified,
                    kind="method" if in_class else "function",
                    header_start=node.start_byte,
                    header_end=_header_end(body),
                    body=(body.start_byte, body.end_byte),
                    full=(wrapper.start_byte, wrapper.end_byte),
                    decorators=decorators,
                )
            )
        is_class = node.type == "class_definition"
        stack.extend((child, qualified, is_class) for child in reversed(node.named_children))
    return found


def _assigned_name(left: Node | None) -> str:
    if left is None:
        return ""
    if left.type == "member_expression":
        return _text(left.child_by_field_name("property"))
    return _text(left) if left.type == "identifier" else ""


# parent node type -> (field holding the function value, field holding the name)
_BINDERS: Final = {
    "variable_declarator": ("value", "name"),
    "pair": ("value", "key"),
    "field_definition": ("value", "property"),
    "public_field_definition": ("value", "name"),
}


def _binding_name(node: Node) -> str:
    """The name a function value is bound to: ``const f = ...``, ``a.b = ...``, ``key: ...``."""
    parent = node.parent
    if parent is None:
        return ""
    if parent.type == "assignment_expression":
        right = parent.child_by_field_name("right")
        return _assigned_name(parent.child_by_field_name("left")) if right == node else ""
    fields = _BINDERS.get(parent.type)
    if fields is None or parent.child_by_field_name(fields[0]) != node:
        return ""
    named = parent.child_by_field_name(fields[1])
    return _text(named if named is not None else parent.child_by_field_name("property"))


def _decorators_of(node: Node) -> list[tuple[int, int]]:
    """A method's decorators: children of the node, or the ``decorator`` siblings just before it.

    The TypeScript and JavaScript grammars put a class member's decorators in the class body,
    before the member, not inside it, so both places are searched.
    """
    spans = [(c.start_byte, c.end_byte) for c in node.children if c.type == "decorator"]
    before = node.prev_sibling
    leading: list[tuple[int, int]] = []
    while before is not None and before.type == "decorator":
        leading.append((before.start_byte, before.end_byte))
        before = before.prev_sibling
    return [*reversed(leading), *spans]


def _javascript_functions(root: Node) -> list[_Raw]:
    found: list[_Raw] = []
    stack: list[tuple[Node, str]] = [(root, "")]
    while stack:
        node, prefix = stack.pop()
        kind = node.type
        name = ""
        function_kind: FunctionKind = "function"
        if kind in _JS_FUNCTION_DECLARATIONS:
            name = _text(node.child_by_field_name("name"))
        elif kind == "method_definition":
            name = _text(node.child_by_field_name("name"))
            function_kind = "method"
        elif kind in _JS_FUNCTION_VALUES:
            name = _binding_name(node)
            parent = node.parent
            if parent is not None and parent.type in _JS_FIELDS:
                function_kind = "method"
        elif kind in _JS_CLASSES:
            name = _text(node.child_by_field_name("name")) or _binding_name(node)
        qualified = _qualify(prefix, name) if name else prefix
        body = node.child_by_field_name("body")
        if name and kind not in _JS_CLASSES and body is not None:
            decorators = _decorators_of(node)
            header_start = next(
                (child.start_byte for child in node.children if child.type != "decorator"),
                node.start_byte,
            )
            full_start = min([node.start_byte, *(start for start, _ in decorators)])
            found.append(
                _Raw(
                    name=name,
                    qualified=qualified,
                    kind=function_kind,
                    header_start=header_start,
                    header_end=_header_end(body),
                    body=(body.start_byte, body.end_byte),
                    full=(full_start, node.end_byte),
                    decorators=decorators,
                )
            )
        stack.extend((child, qualified) for child in reversed(node.named_children))
    return found


def function_ranges(parsed: ParsedFile, spec: LanguageSpec | None) -> tuple[FunctionRange, ...]:
    """Every named function and method of ``parsed`` with exact ranges, in source order.

    A file with no syntax tree (a timed-out parse), an unsupported language, or no registered
    ``spec`` yields ``()``.
    """
    line_index = parsed.line_index
    if spec is None or parsed.tree is None or line_index is None:
        return ()
    root = parsed.tree.root_node
    if parsed.language is Language.PYTHON:
        raws = _python_functions(root)
    elif parsed.language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        raws = _javascript_functions(root)
    else:
        return ()
    raws.sort(key=lambda raw: (raw.full[0], -raw.full[1]))
    spans: list[tuple[int, int]] = []
    for raw in raws:
        spans.append((raw.header_start, raw.header_end))
        spans.append(raw.body)
        spans.append(raw.full)
        spans.extend(raw.decorators)
    locations = line_index.locations(parsed.path, spans)
    results: list[FunctionRange] = []
    cursor = 0
    for raw in raws:
        header, body, full = locations[cursor : cursor + 3]
        count = len(raw.decorators)
        decorators = tuple(locations[cursor + 3 : cursor + 3 + count])
        cursor += 3 + count
        results.append(
            FunctionRange(
                symbol_name=raw.name,
                qualified_name=raw.qualified,
                kind=raw.kind,
                header=header,
                body=body,
                full=full,
                decorators=decorators,
            )
        )
    return tuple(results)


__all__ = ["FunctionKind", "FunctionRange", "function_ranges"]
