"""Reflected cross-site scripting (CWE-79): caller input written into an HTML response unescaped.

Owning epic: E13. MVP; extended by E16.

Sinks: ``res.send``/``write``/``end`` (and ``response``/``reply``) and ``render_template_string``,
``Markup``, ``HTMLResponse``, ``make_response`` and ``HttpResponse`` for response bodies, which fire
when the body is HTML built by interpolation with a part taken from the caller; and
``innerHTML``/``outerHTML`` assignments, ``document.write`` and ``insertAdjacentHTML``, which fire
on any unescaped non-literal part. A part passed through an escaping function (``escapeHtml``,
``escape``, ``sanitize``, ``bleach.clean``) is the safe form.
"""

import re
from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    enclosing_function,
    is_escaped,
    is_literal,
    is_request_derived,
    last_segment,
    resolve_string,
    static_text,
    string_parts,
    text_of,
)
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="reflected-xss",
    cwe=79,
    severity=Severity.MEDIUM,
    message="Input from the caller is written into an HTML response without escaping.",
)
RESPONSE_ROOTS: Final = frozenset({"res", "response", "resp", "reply"})
RESPONSE_METHODS: Final = frozenset({"send", "write", "end"})
PYTHON_RESPONSES: Final = frozenset(
    {"render_template_string", "markup", "htmlresponse", "make_response", "httpresponse"}
)
DOM_SINKS: Final = frozenset({"document.write", "document.writeln"})
DOM_PROPERTIES: Final = frozenset({"innerHTML", "outerHTML"})
HTML_FRAGMENT: Final = re.compile(r"<[A-Za-z/!]")


class XssMatcher(NodeMatcher):
    """Finds HTML built from caller input and written out without escaping."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES | {"assignment_expression"}

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for an unescaped HTML sink at this node."""
        function = enclosing_function(node)
        if node.type == "assignment_expression":
            target = node.child_by_field_name("left")
            value = node.child_by_field_name("right")
            member = target.child_by_field_name("property") if target is not None else None
            written = text_of(member) if member is not None else ""
            if (
                value is not None
                and written in DOM_PROPERTIES
                and self._unescaped(value, function, ctx, strong=True)
            ):
                yield Hit(RULE, node)
            return
        name = callee_name(node) or ""
        owner, _, method = name.partition(".")
        arguments, _ = call_arguments(node)
        if not arguments:
            return
        if name in DOM_SINKS or last_segment(name) == "insertAdjacentHTML":
            html = arguments[-1]
            strong = True
        elif (owner in RESPONSE_ROOTS and method in RESPONSE_METHODS) or (
            name.lower() in PYTHON_RESPONSES and node.type == "call"
        ):
            html, strong = arguments[0], False
        else:
            return
        if self._unescaped(html, function, ctx, strong=strong):
            yield Hit(RULE, node)

    @staticmethod
    def _unescaped(html: Node, function: Node | None, ctx: FileContext, *, strong: bool) -> bool:
        body = resolve_string(html, function, ctx.root)
        parts = string_parts(body)
        if parts is None:
            return strong and (
                not is_literal(body)
                and not is_escaped(body)
                and is_request_derived(body, function, ctx.root)
            )
        if not strong and not HTML_FRAGMENT.search(static_text(body)):
            return False
        return any(
            not is_literal(part)
            and not is_escaped(part)
            and (strong or is_request_derived(part, function, ctx.root))
            for part in parts
        )
