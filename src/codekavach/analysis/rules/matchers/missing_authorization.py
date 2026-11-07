"""Missing authorisation (CWE-862): an account-scoped route that checks nobody's identity.

Owning epic: E13. MVP; extended by E16.

Python: a function declared with ``@app.route``/``@router.get`` whose path is account-scoped
(see ``routes``) and that has no authentication decorator, no ``Depends(...)`` parameter and no
inline check (``abort(401)``, ``current_user``, ``g.user``). JavaScript: a
``router.get("/accounts/...")`` call with no authentication middleware among its arguments and no
``req.user``/``req.session`` check in an inline handler. A route that is not account-scoped
(``/health``, ``/login``) is never reported.
"""

import re
from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.routes import decorator_text, python_route, route_of_call
from codekavach.analysis.rules.syntax import CALL_TYPES, FUNCTION_TYPES, text_of
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="missing-authorization",
    cwe=862,
    severity=Severity.HIGH,
    message="An account-scoped route has no authentication or authorisation check.",
)
AUTH_NAME: Final = re.compile(
    r"auth|login|permission|jwt|require|protect|guard|role|session|token|secure|depends",
    re.IGNORECASE,
)
AUTH_BODY: Final = re.compile(
    r"abort\(\s*40[13]|HTTPException|current_user|g\.user|request\.user|req\.user|req\.session|"
    r"isAuthenticated|is_authenticated|status\(\s*40[13]\s*\)",
)


class MissingAuthorizationMatcher(NodeMatcher):
    """Finds account-scoped routes with no authentication in sight."""

    node_types: ClassVar[frozenset[str]] = frozenset({"function_definition"}) | CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for an unauthenticated account-scoped route."""
        if node.type == "function_definition":
            yield from self._python(node)
        else:
            yield from self._javascript(node)

    @staticmethod
    def _python(function: Node) -> Iterator[Hit]:
        route = python_route(function)
        if route is None or not route.is_account_scoped:
            return
        parameters = function.child_by_field_name("parameters")
        body = function.child_by_field_name("body")
        checked = " ".join(
            [
                decorator_text(function),
                text_of(parameters) if parameters is not None else "",
            ]
        )
        if AUTH_NAME.search(checked) or (body is not None and AUTH_BODY.search(text_of(body))):
            return
        yield Hit(RULE, function)

    @staticmethod
    def _javascript(call: Node) -> Iterator[Hit]:
        route = route_of_call(call)
        if route is None or call.type != "call_expression" or not route.is_account_scoped:
            return
        holder = call.child_by_field_name("arguments")
        handlers = holder.named_children[1:] if holder is not None else []
        for handler in handlers:
            if handler.type in FUNCTION_TYPES:
                if AUTH_BODY.search(text_of(handler)):
                    return
            elif AUTH_NAME.search(text_of(handler)):
                return
        yield Hit(RULE, call)
