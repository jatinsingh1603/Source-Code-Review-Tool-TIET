"""Route recognition shared by the authorisation and object-reference matchers.

Owning epic: E13. MVP; extended by E16.

A Python route is a function decorated with ``@app.route("/path")`` or ``@router.get("/path")``
(Flask, FastAPI, Blueprint); a JavaScript route is a call such as ``router.get("/path", ...)``
(Express, Koa router). The path is what tells an account-scoped route from ``/health`` or
``/login``: a route is *account-scoped* when its path names accounts, customers, loans, transfers,
statements, payments, beneficiaries or cards.
"""

import re
from dataclasses import dataclass
from typing import Final

from tree_sitter import Node

from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    is_static_string,
    last_segment,
    static_text,
    text_of,
)

HTTP_VERBS: Final = frozenset(
    {"get", "post", "put", "patch", "delete", "route", "api_route", "all"}
)
ACCOUNT_SCOPED: Final = re.compile(
    r"account|customer|loan|transfer|statement|payment|beneficiar|card|deposit", re.IGNORECASE
)
PATH_PARAMETER: Final = re.compile(r"<(?:[A-Za-z_]+:)?(\w+)>|\{(\w+)\}|:(\w+)")


@dataclass(frozen=True, slots=True)
class Route:
    """A recognised route: its path and the node of the call that declares it."""

    path: str
    declaration: Node

    @property
    def parameters(self) -> frozenset[str]:
        """The names in the path: ``<id>``, ``<int:id>``, ``{id}`` or ``:id``."""
        return frozenset(
            name for match in PATH_PARAMETER.finditer(self.path) for name in match.groups() if name
        )

    @property
    def is_account_scoped(self) -> bool:
        """Whether the path names something a caller must be authorised to touch."""
        return ACCOUNT_SCOPED.search(self.path) is not None


def route_of_call(call: Node) -> Route | None:
    """The route ``call`` declares (``app.route("/x")``, ``router.get("/x", h)``), or ``None``."""
    if call.type not in CALL_TYPES:
        return None
    name = callee_name(call)
    if name is None or "." not in name or last_segment(name).lower() not in HTTP_VERBS:
        return None
    arguments, _ = call_arguments(call)
    if not arguments or not is_static_string(arguments[0]):
        return None
    path = static_text(arguments[0])
    return Route(path, call) if path.startswith("/") else None


def _declares_route(expression: Node) -> bool:
    return route_of_call(expression) is not None


def python_route(function_definition: Node) -> Route | None:
    """The route a decorated Python function serves, or ``None``."""
    parent = function_definition.parent
    if parent is None or parent.type != "decorated_definition":
        return None
    for decorator in parent.named_children:
        if decorator.type != "decorator":
            continue
        expression = decorator.named_children[0] if decorator.named_children else None
        route = route_of_call(expression) if expression is not None else None
        if route is not None:
            return route
    return None


def decorator_text(function_definition: Node) -> str:
    """The text of every decorator except the route declaration itself."""
    parent = function_definition.parent
    if parent is None or parent.type != "decorated_definition":
        return ""
    texts: list[str] = []
    for decorator in parent.named_children:
        expression = decorator.named_children[0] if decorator.named_children else None
        if (
            decorator.type == "decorator"
            and expression is not None
            and not _declares_route(expression)
        ):
            texts.append(text_of(expression))
    return "\n".join(texts)
