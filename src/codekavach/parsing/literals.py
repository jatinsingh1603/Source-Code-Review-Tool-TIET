"""Pure, language-agnostic classification of a string literal's content (E07-02).

Owning epic: E07.

``classify_literal`` decides how much of a string survives the privacy layer's shaping pass
(``docs/ARCHITECTURE.md`` section 6.2 step 4): an SQL skeleton, a URL scheme, a path separator
or a format specifier is security-relevant shape that must be preserved, while an ordinary
sentence is domain text that should not be. The function takes a little structural context
(``LiteralContext``) rather than a tree-sitter node, so it stays pure and is tested as a plain
table of inputs and expected kinds, independent of any parser.

Rules are tried in a fixed order and the first match wins (``docs/research/INSIGHTS.md`` section
3.3 item 7): an SQL statement that also contains ``%s`` classifies as ``sql``, not ``format``,
because the SQL skeleton is the evidence of CWE-89.
"""

import re
from dataclasses import dataclass
from typing import Literal

LiteralKind = Literal["sql", "url", "path", "format", "regex", "natural"]

_SQL_LEADING = (
    "select ",
    "insert ",
    "update ",
    "delete ",
    "with ",
    "create ",
    "alter ",
    "drop ",
)
_SQL_SECONDARY_KEYWORDS = ("where", "join", "order by", "group by")
_SQL_FROM = re.compile(r"\bfrom\b")

_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_URL_PROTOCOL_RELATIVE = re.compile(r"^//[a-zA-Z0-9]")
_URL_FIXED_PREFIXES = ("mailto:", "jdbc:")

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_PATH_RELATIVE_PREFIXES = ("./", "../", "~/")

_FORMAT_PRINTF = re.compile(r"%[-+0 #]*\d*(?:\.\d+)?[sdifgxXoc]")
_FORMAT_NAMED = re.compile(r"%\(\w+\)[sdifgxXoc]")
_FORMAT_BRACE = re.compile(r"\{[\w]*\}")
_FORMAT_SHELL_STYLE = re.compile(r"\$\{[^{}]*\}")

_REGEX_CALLEES = frozenset(
    {
        "re.compile",
        "re.match",
        "re.search",
        "re.fullmatch",
        "re.findall",
        "re.finditer",
        "re.sub",
        "re.split",
        "new RegExp",
        "RegExp",
    }
)


@dataclass(frozen=True, slots=True)
class LiteralContext:
    """The little structural context ``classify_literal`` needs to be accurate.

    ``callee_text`` is the enclosing call's callee, when the literal is one of its arguments
    (``"re.compile"``, ``"cur.execute"``). ``assignment_target`` is the name on the left of a
    ``=`` when the literal is the right-hand side. ``joined_text`` is the concatenation of every
    fragment of an adjacent-literal or ``+``-joined group, when the literal is part of one;
    classification then runs against the joined text, not the individual fragment.
    ``is_regex_literal`` is true for a JavaScript regular-expression literal node, which carries
    no separate text to classify by content.
    """

    callee_text: str | None = None
    assignment_target: str | None = None
    joined_text: str | None = None
    is_regex_literal: bool = False


def _looks_like_sql(folded: str) -> bool:
    if folded.startswith(_SQL_LEADING):
        return True
    return bool(_SQL_FROM.search(folded)) and any(k in folded for k in _SQL_SECONDARY_KEYWORDS)


def _looks_like_url(text: str) -> bool:
    if _URL_SCHEME.match(text) or _URL_PROTOCOL_RELATIVE.match(text):
        return True
    return text.startswith(_URL_FIXED_PREFIXES)


def _looks_like_path(text: str) -> bool:
    if _WINDOWS_DRIVE.match(text):
        return True
    if text.startswith(_PATH_RELATIVE_PREFIXES):
        return True
    return ("/" in text or "\\" in text) and not any(char.isspace() for char in text)


def _looks_like_format(text: str) -> bool:
    return bool(
        _FORMAT_PRINTF.search(text)
        or _FORMAT_NAMED.search(text)
        or _FORMAT_BRACE.search(text)
        or _FORMAT_SHELL_STYLE.search(text)
    )


def _looks_like_regex(context: LiteralContext) -> bool:
    if context.is_regex_literal:
        return True
    return context.callee_text in _REGEX_CALLEES


def classify_literal(text: str, context: LiteralContext | None = None) -> LiteralKind:
    """Classify one string literal's content; the first matching rule, in this order, wins.

    The regex check runs first, ahead of the content-based rules the issue lists before it:
    it is a structural, context-only signal (the literal is an argument to a known
    regular-expression API, or is itself a regular-expression literal node), and a regex
    pattern's own syntax (``{3}``, bracketed character classes, ``/``-escapes) otherwise false
    -positives against the ``format`` and ``path`` content heuristics. A table test
    (``re.match("[0-9]{3}-[0-9]{4}")``) pins this ordering.
    """
    ctx = context if context is not None else LiteralContext()
    if _looks_like_regex(ctx):
        return "regex"
    subject = ctx.joined_text if ctx.joined_text is not None else text
    folded = subject.strip().lower()
    if _looks_like_sql(folded):
        return "sql"
    if _looks_like_url(subject.strip()):
        return "url"
    if _looks_like_path(subject.strip()):
        return "path"
    if _looks_like_format(subject):
        return "format"
    return "natural"
