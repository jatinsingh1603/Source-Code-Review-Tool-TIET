"""Server-side request forgery (CWE-918): an outbound request to a caller-chosen URL.

Owning epic: E13. MVP; extended by E16.

Sinks: ``requests``, ``httpx`` and ``urllib`` calls in Python; ``fetch``, ``axios``, ``got``,
``http`` and ``https`` requests in JavaScript. The matcher fires when the URL argument uses a
parameter of the enclosing function, ``request`` data or a local taken from them. The safe form
is an allow-list check in the same function: any name that says ``allow`` or ``blocklist``,
``validate_url``, ``is_safe_url`` and the like. A URL built only from constants never fires.
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
    identifiers_in,
    is_request_derived,
)
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="ssrf",
    cwe=918,
    severity=Severity.HIGH,
    message="An outbound request goes to a URL chosen by the caller, with no allow-list check.",
)
_VERBS: Final = ("get", "post", "put", "patch", "delete", "head", "options", "request", "stream")
_PYTHON_CLIENTS: Final = ("requests", "httpx", "session")
PYTHON_SINKS: Final = frozenset(
    [f"{module}.{verb}" for module in _PYTHON_CLIENTS for verb in _VERBS]
    + ["urllib.request.urlopen", "urlopen", "urllib2.urlopen", "aiohttp.request"]
)
JAVASCRIPT_SINKS: Final = frozenset(
    ["fetch", "axios", "got", "needle", "request", "superagent", "http.get", "https.get",
     "http.request", "https.request"]
    + [f"axios.{verb}" for verb in _VERBS]
    + [f"got.{verb}" for verb in _VERBS]
)  # fmt: skip
SAFE_NAME: Final = re.compile(
    r"allow|block(ed|list)|deny|(validate|verify|check|is)_?(safe_?)?(url|host)|safe_?url|"
    r"is_?internal|is_?private_?(ip|host)",
    re.IGNORECASE,
)


def _url_argument(name: str, arguments: list[Node]) -> Node | None:
    """The URL argument: the second one for ``requests.request(method, url)``, else the first."""
    is_generic = name.endswith(".request") and name.split(".", maxsplit=1)[0] in _PYTHON_CLIENTS
    index = 1 if is_generic else 0
    return arguments[index] if len(arguments) > index else None


class SsrfMatcher(NodeMatcher):
    """Finds outbound requests whose URL the caller controls."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for an outbound request to an unchecked caller-controlled URL."""
        name = (callee_name(node) or "").lower()
        sinks = PYTHON_SINKS if node.type == "call" else JAVASCRIPT_SINKS
        if name not in sinks:
            return
        arguments, _ = call_arguments(node)
        url = _url_argument(name, arguments)
        function = enclosing_function(node)
        if url is None or not is_request_derived(url, function, ctx.root):
            return
        scope = function if function is not None else ctx.root
        if any(SAFE_NAME.search(word) for word in identifiers_in(scope)):
            return
        yield Hit(RULE, node)
