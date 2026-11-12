"""Framework entry points: where untrusted data enters a function as a parameter (E17-03).

Owning epic: E17. The catalogues name the request *objects* (``request.args``, ``req.query``); what
they cannot name is a value the framework hands to a handler as an argument, such as the
``account_id`` of ``@app.route("/accounts/<account_id>")``. This module reads the decorators of a
lowered function and marks those parameters as tainted sources of the right kind, so the analysis
starts where the data really enters.

Modelled (Python): Flask and Quart ``route`` path converters, FastAPI and Starlette verb
decorators (every parameter except the framework's own), Django ``path()`` views are covered by
the request-object sources, Click commands (``cli``), Celery and Dramatiq tasks (``message``).
Modelled (JavaScript and TypeScript): an Express or Fastify route handler is a function whose first
parameter is ``req``/``request`` and whose second is ``res``/``response``/``reply``/``next``
(anonymous callbacks passed to ``app.get(path, ...)`` have no decorator to read, so the signature
is the evidence). Its request parameter is seeded as one tainted value, so ``helper(req)`` carries
taint into the functions the handler calls. A read of a request value the catalogue names
(``req.query.id``) replaces that seed with the catalogue source, so a direct flow is reported once,
with the catalogue's source id. Message consumers and scheduled tasks beyond the decorators above
are not modelled.
"""

import re
from typing import Final

from codekavach.analysis.taint.ir import IRFunction
from codekavach.analysis.taint.propagate import Seed

HTTP_VERBS: Final = r"(?:route|get|post|put|delete|patch|head|options|api_route|websocket)"
_FLASK = re.compile(r"\.route\(\s*[rbf]?['\"]([^'\"]*)['\"]")
_VERB = re.compile(rf"\.{HTTP_VERBS}\(\s*[rbf]?['\"]([^'\"]*)['\"]")
_CLICK = re.compile(r"\b(?:click|typer)\b.*\.(?:command|group)\(|\.command\(")
_TASK = re.compile(r"\b(?:shared_task|task|actor)\b")
_CONVERTER = re.compile(r"<(?:[A-Za-z_]+:)?([A-Za-z_][A-Za-z0-9_]*)>")
_BRACES = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}")
FRAMEWORK_PARAMS: Final = frozenset(
    {
        "self",
        "cls",
        "request",
        "response",
        "req",
        "res",
        "db",
        "session",
        "conn",
        "background_tasks",
    }
)
_REQUEST_NAMES: Final = frozenset({"req", "request"})
_RESPONSE_NAMES: Final = frozenset({"res", "response", "reply", "next"})
HTTP_HANDLER: Final = "http_handler"
CLI_ENTRY: Final = "cli_entry"
MESSAGE_CONSUMER: Final = "message_consumer"


def is_request_handler(function: IRFunction) -> bool:
    """Whether the parameters read like an Express or Fastify handler ``(req, res|reply|next)``."""
    return (
        len(function.params) >= 2
        and function.params[0] in _REQUEST_NAMES
        and function.params[1] in _RESPONSE_NAMES
    )


def entry_kind(function: IRFunction) -> str | None:
    """The kind of entry point ``function`` is, from its decorators, or ``None``."""
    if is_request_handler(function):
        return HTTP_HANDLER
    for decorator in function.decorators:
        if _VERB.search(decorator):
            return HTTP_HANDLER
        if _CLICK.search(decorator):
            return CLI_ENTRY
        if _TASK.search(decorator):
            return MESSAGE_CONSUMER
    return None


def entry_seeds(function: IRFunction) -> dict[str, Seed]:  # noqa: PLR0912 - one branch per framework
    """Parameters of ``function`` that the framework fills with outside data, as seeds."""
    seeds: dict[str, Seed] = {}
    if is_request_handler(function):
        seeds[function.params[0]] = (
            "framework.request",
            "http_param",
            f"request parameter {function.params[0]}",
        )
    for decorator in function.decorators:
        flask = _FLASK.search(decorator)
        verb = _VERB.search(decorator)
        if verb is not None:
            path = (flask or verb)[1]
            named = set(_CONVERTER.findall(path))
            braces = set(_BRACES.findall(path))
            if flask is not None and not braces:
                wanted = named  # Flask: only path converters
            else:
                wanted = set(function.params) - FRAMEWORK_PARAMS  # FastAPI style
            for name in function.params:
                if name in wanted and name not in FRAMEWORK_PARAMS:
                    seeds[name] = (
                        "framework.http_handler",
                        "http_param",
                        f"route parameter {name}",
                    )
        elif _CLICK.search(decorator):
            for name in function.params:
                if name not in FRAMEWORK_PARAMS:
                    seeds[name] = ("framework.cli_entry", "cli", f"command argument {name}")
        elif _TASK.search(decorator):
            for name in function.params:
                if name not in FRAMEWORK_PARAMS:
                    seeds[name] = ("framework.message_consumer", "message", f"message field {name}")
    return seeds
