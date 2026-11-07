"""SQL injection (CWE-89): a query built by interpolation reaches a database call.

Owning epic: E13. MVP; extended by E16.

Sink list: the ``execute`` family, ``raw`` and ``query`` calls. The matcher fires when the first
argument is a string built at run time (concatenation, ``%``, ``.format``, an f-string or a template
literal with a substitution) or a local name assigned one, and the static text reads as SQL. It does
not fire on a literal query with bound parameters, which is the safe form.
"""

from collections.abc import Iterator
from typing import ClassVar, Final

from tree_sitter import Node

from codekavach.analysis.rules.engine import FileContext, Hit, NodeMatcher, Rule
from codekavach.analysis.rules.syntax import (
    CALL_TYPES,
    call_arguments,
    callee_name,
    enclosing_function,
    last_segment,
    resolve_string,
    static_text,
    string_parts,
)
from codekavach.core.models import Severity

RULE: Final = Rule(
    slug="sql-injection",
    cwe=89,
    severity=Severity.HIGH,
    message="A database call receives query text that was built by string interpolation.",
)
STRONG_SINKS: Final = frozenset(
    {"execute", "executemany", "executescript", "executeraw", "queryraw", "$queryrawunsafe",
     "$executerawunsafe", "read_sql", "read_sql_query", "raw"}
)  # fmt: skip
WEAK_SINKS: Final = frozenset({"query", "run", "all", "each", "prepare"})
SQL_START: Final = (
    "select", "insert", "update", "delete", "with", "replace", "create", "drop", "alter", "merge",
    "call", "exec", "truncate", "grant", "revoke", "pragma", "set ",
)  # fmt: skip


def _reads_as_sql(text: str) -> bool:
    return text.lstrip().lower().startswith(SQL_START)


class SqlInjectionMatcher(NodeMatcher):
    """Finds queries assembled from variable parts before they reach the database."""

    node_types: ClassVar[frozenset[str]] = CALL_TYPES

    def visit(self, node: Node, ctx: FileContext) -> Iterator[Hit]:
        """Yield a hit for a database call whose query text is interpolated."""
        name = last_segment(callee_name(node)).lower()
        if name not in STRONG_SINKS and name not in WEAK_SINKS:
            return
        arguments, _ = call_arguments(node)
        if not arguments:
            return
        query = resolve_string(arguments[0], enclosing_function(node), ctx.root)
        parts = string_parts(query)
        if not parts:
            return
        text = static_text(query)
        if name in WEAK_SINKS and not _reads_as_sql(text):
            return
        if name in STRONG_SINKS and text.strip() and not _reads_as_sql(text):
            return
        yield Hit(RULE, node)
