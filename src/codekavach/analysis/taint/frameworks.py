"""Framework entry points: where untrusted data enters a function as a parameter (E17-03).

Owning epic: E17. The catalogues name the request *objects* (``request.args``, ``req.query``); what
they cannot name is a value the framework hands to a handler as an argument, such as the
``account_id`` of ``@app.route("/accounts/<account_id>")``. This module reads the decorators of a
lowered function and marks those parameters as tainted sources of the right kind, so the analysis
starts where the data really enters.

Modelled (Python): Flask and Quart ``route`` path converters, FastAPI and Starlette verb
decorators (every parameter except the framework's own), Django ``path()`` views are covered by
the request-object sources, Click commands (``cli``), Celery and Dramatiq tasks (``message``).
Modelled (JavaScript and TypeScript): Express, Koa and Fastify handlers read ``req.*`` through the
catalogue sources, so no parameter of a JavaScript handler is seeded; what interprocedural taint
adds there is the flow of those values into functions of other files through ``require`` and
``import``. Message consumers and scheduled tasks beyond the decorators above are not modelled.
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
HTTP_HANDLER: Final = "http_handler"
CLI_ENTRY: Final = "cli_entry"
MESSAGE_CONSUMER: Final = "message_consumer"


def entry_kind(function: IRFunction) -> str | None:
    """The kind of entry point ``function`` is, from its decorators, or ``None``."""
    for decorator in function.decorators:
        if _VERB.search(decorator):
            return HTTP_HANDLER
        if _CLICK.search(decorator):
            return CLI_ENTRY
        if _TASK.search(decorator):
            return MESSAGE_CONSUMER
    return None


def entry_seeds(function: IRFunction) -> dict[str, Seed]:
    """Parameters of ``function`` that the framework fills with outside data, as seeds."""
    seeds: dict[str, Seed] = {}
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
