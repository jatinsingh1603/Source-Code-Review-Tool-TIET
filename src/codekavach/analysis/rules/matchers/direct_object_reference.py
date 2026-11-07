"""Insecure direct object reference (CWE-639): a record fetched by a caller-supplied id, unchecked.

Owning epic: E13. MVP; extended by E16.

Sink list: lookup calls by record id (``get_account``, ``find_account_by_id``, ``get_statement``,
``findById``, ``findOne`` and the like; see ``LOOKUP``). Python: the call sits in a route function
and takes one of the route's path parameters. JavaScript: the call takes ``req`` data. The safe form
is an ownership check in the same function, recognised by a name that says owner, current user,
session, permission or tenant, or by the lookup being scoped to a ``g.user``/``req.user`` argument.
"""

import re
from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.routes import python_route
from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    enclosing_function,
    identifiers_in,
    is_request_derived,
    last_segment,
    text_of,
)
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="insecure-direct-object-reference",
    cwe=639,
    severity=Severity.HIGH,
    message="A record is fetched by an identifier from the caller with no ownership check.",
)
LOOKUP: Final = re.compile(
    r"^(find|get|fetch|load|read|select|retrieve)_?(by_?)?"
    r"(id|pk|unique|one|first|account|statement|customer|loan|transaction|beneficiary|card|order|"
    r"invoice|document|record|profile|payment)\w*$",
    re.IGNORECASE,
)
OWNERSHIP: Final = re.compile(
    r"owner|owned|current_?user|belongs|g\.user|request\.user|req\.user|req\.session|session|"
    r"authori[sz]|has_?access|permission|tenant|is_?mine",
    re.IGNORECASE,
)


class DirectObjectReferenceMatcher(NodeMatcher):
    """Finds record lookups by a caller-supplied id with no ownership check."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for a lookup by caller-supplied id in a function with no ownership check."""
        function = enclosing_function(node)
        if function is None or not LOOKUP.match(last_segment(callee_name(node))):
            return
        arguments, _ = call_arguments(node)
        if self._takes_caller_id(node, function, arguments, ctx) and not OWNERSHIP.search(
            text_of(function)
        ):
            yield Hit(RULE, node)

    @staticmethod
    def _takes_caller_id(
        call: Node, function: Node, arguments: list[Node], ctx: FileContext
    ) -> bool:
        """Whether an argument is a path parameter (Python route) or request data (JavaScript)."""
        if call.type != "call":
            return any(is_request_derived(item, function, ctx.root) for item in arguments)
        route = python_route(function)
        if route is None:
            return False
        used = {word for item in arguments for word in identifiers_in(item)}
        return bool(used & route.parameters)
