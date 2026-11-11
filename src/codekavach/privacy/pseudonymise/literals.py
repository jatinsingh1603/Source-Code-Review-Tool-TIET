"""String literal shaping: keep the security-relevant skeleton, replace the domain vocabulary.

Owning epic: E09. Issue E09-03. Normative layout: docs/ARCHITECTURE.md section 6.2 step 4.

A literal is shaped per its kind (``LiteralSpan.kind``, classified by E07-02). The shape that is the
security evidence survives: the SQL statement skeleton and its parameter markers, the format
specifiers, the path separators and the URL scheme, the regular-expression metacharacters. The words
that name the client's business do not: identifiers become pseudonyms, words become a filler of the
same length, and numbers go through ``generalise_number``.

Input and output are the literal's *content*, not its delimiters: the caller re-wraps the result in
the quotes it already has. No shaper emits a quote, a backslash or a newline that the input did not
contain, so a shaped literal still tokenises as one string literal of the same delimiter form.

Placeholder tokens from E08 (``<SECRET:...>``) are opaque atoms: the text is split around them and
each token passes through every shaper byte for byte.

**Nothing is kept because of its spelling.** A word is kept only when the allowlist says it is
public (or it is an SQL keyword, a format directive or a placeholder). A word that merely looks
like a pseudonym (``fn_1``, ``col_3``) is replaced like any other: an original identifier spelled
that way must not reach the provider (I6). The price is that shaping is not idempotent; the
pipeline shapes each literal once, from the original.

**Known limits.** A shaped SQL statement still reveals a table count, its column count, its
keywords and the parameter markers; a shaped path still reveals its depth and extension. These
are measured by the leakage harness (metric M3, docs/research/INSIGHTS.md section 4.3), not
claimed to be harmless. Nothing here claims resistance to identifier recovery.

**Fail closed.** Where a shaper cannot be sure a construct is safe to keep, it replaces it. A
regular expression whose shaped form does not compile is replaced by a filler pattern, not sent as
it was, and counted in the provenance as a fallback.
"""

import re
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from codekavach.core.models import PrivacyLevel
from codekavach.privacy.detect.mask import PLACEHOLDER_MASK_PATTERN
from codekavach.privacy.errors import PseudonymError
from codekavach.privacy.pseudonymise.generator import (
    PseudonymGenerator,
    PseudonymKind,
)
from codekavach.privacy.pseudonymise.numbers import NumberContext, NumberSite, generalise_number

if TYPE_CHECKING:
    from codekavach.parsing.models import LiteralSpan

FILLER: Final = "x"
NATURAL_MIN_LENGTH: Final = 4
_TEMPLATE_SEGMENT: Final = re.compile(r"^(\{[^{}]*\}|:[A-Za-z_]\w*|\*)$")
_WORD: Final = re.compile(r"\w+")
_FORMAT_MARKER: Final = re.compile(
    r"%\([A-Za-z_]\w*\)[sdif]|%[sdifr]|\?|\$\d+|:[A-Za-z_]\w*|" + PLACEHOLDER_MASK_PATTERN.pattern
)


class PublicAllowlist(Protocol):
    """The public API names a shaper keeps verbatim (the E09-02 allowlist satisfies this).

    Only ``is_public`` is used. A word is kept verbatim when it is public; there is no other way to
    keep an identifier, so an empty allowlist shapes everything.
    """

    def is_public(self, word: str) -> bool:
        """True when ``word`` is a public API name that may appear in a payload unchanged."""
        ...


@dataclass(frozen=True, slots=True)
class ShapeDisplay:
    """The display prefixes of SQL pseudonyms: ``field_3`` shows as ``col_3`` by default."""

    column_prefix: str = "col"
    table_prefix: str = "tbl"


@dataclass(frozen=True, slots=True)
class ShapeProvenance:
    """What shaping one literal kept and replaced, as counts only; never the content."""

    kind: str
    tokens_kept: int
    tokens_replaced: int
    fallbacks: int = 0


@dataclass(slots=True)
class _Context:
    generator: PseudonymGenerator
    allowlist: PublicAllowlist
    display: ShapeDisplay
    kept: int = 0
    replaced: int = 0
    fallbacks: int = 0

    def keep(self, count: int = 1) -> None:
        self.kept += count

    def replace(self, count: int = 1) -> None:
        self.replaced += count

    def is_kept_word(self, word: str) -> bool:
        return self.allowlist.is_public(word)

    def pseudonym(self, kind: PseudonymKind, original: str, prefix: str | None = None) -> str:
        token = self.generator.token(kind, original)
        if prefix is None:
            return token
        return f"{prefix}_{token.split('_', 1)[1]}"


def _filler(word: str) -> str:
    return FILLER * len(word)


def _fill_words(text: str, ctx: _Context) -> str:
    """Replace every word that is not kept by a filler of the same length."""

    def replace(match: re.Match[str]) -> str:
        word = match.group(0)
        if ctx.is_kept_word(word):
            ctx.keep()
            return word
        ctx.replace()
        return _filler(word)

    return _WORD.sub(replace, text)


def _name_of(name: str, ctx: _Context) -> str:
    """A placeholder or argument name: public names stay, internal ones become a pseudonym."""
    if name == "" or name.isdigit() or ctx.is_kept_word(name):
        ctx.keep()
        return name
    ctx.replace()
    return ctx.pseudonym(PseudonymKind.VAR, name)


# ---- natural -----------------------------------------------------------------------------------


def _shape_natural(text: str, ctx: _Context) -> str:
    if len(text) < NATURAL_MIN_LENGTH:
        ctx.keep()
        return text
    return _fill_words(text, ctx)


# ---- format ------------------------------------------------------------------------------------

_FORMAT_SPEC: Final = re.compile(
    r"%%"
    r"|%\((?P<pname>[^)]*)\)(?P<pspec>[-+ #0]*\d*(?:\.\d+)?[a-zA-Z])"
    r"|%[-+ #0]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[diouxXeEfFgGcrsavwqTtpU]"
    r"|\{\{|\}\}"
    r"|\{(?P<bname>[^{}!:]*)(?P<bspec>[!:][^{}]*)?\}"
    r"|\$\{(?P<sname>[^{}]*)\}"
)


def _shape_format(text: str, ctx: _Context) -> str:
    out: list[str] = []
    position = 0
    for match in _FORMAT_SPEC.finditer(text):
        out.append(_fill_words(text[position : match.start()], ctx))
        ctx.keep()
        if match.group("pname") is not None:
            name = _name_of(match.group("pname"), ctx)
            out.append(f"%({name}){match.group('pspec')}")
        elif match.group("bname") is not None:
            name = _name_of(match.group("bname"), ctx)
            out.append("{" + name + (match.group("bspec") or "") + "}")
        elif match.group("sname") is not None:
            out.append("${" + _name_of(match.group("sname"), ctx) + "}")
        else:
            out.append(match.group(0))
        position = match.end()
    out.append(_fill_words(text[position:], ctx))
    return "".join(out)


# ---- regex -------------------------------------------------------------------------------------


def _class_end(text: str, start: int) -> int:
    """The index of the ``]`` closing the character class that opens at ``start``, or -1."""
    index = start + 1
    if index < len(text) and text[index] == "^":
        index += 1
    if index < len(text) and text[index] == "]":
        index += 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == "]":
            return index
        index += 1
    return -1


def _regex_compiles(pattern: str) -> bool:
    """Whether ``pattern`` compiles; a warning from the compiler never escapes this check."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            re.compile(pattern)
    except (re.error, OverflowError, RecursionError):
        return False
    return True


def _shape_regex_body(text: str, ctx: _Context) -> str | None:
    """Shape a pattern, or return ``None`` when it cannot be shaped safely."""
    out: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            if index + 2 < length and text[index + 1] in "pPN" and text[index + 2] == "{":
                close = text.find("}", index + 3)
                if close == -1:
                    return None
                out.append(text[index : close + 1])
                index = close + 1
            else:
                out.append(text[index : index + 2])
                index += 2
            ctx.keep()
            continue
        if char == "[":
            close = _class_end(text, index)
            if close == -1:
                return None
            out.append(text[index : close + 1])
            ctx.keep()
            index = close + 1
            continue
        if char.isalpha():
            end = index
            while end < length and text[end].isalpha():
                end += 1
            run = text[index:end]
            flags_group = "".join(out[-1:]) == "?" and "".join(out[-2:-1]) == "("
            if len(run) >= NATURAL_MIN_LENGTH and not flags_group:
                out.append(_filler(run))
                ctx.replace()
            else:
                out.append(run)
                ctx.keep()
            index = end
            continue
        out.append(char)
        ctx.keep()
        index += 1
    return "".join(out)


def _shape_regex(text: str, ctx: _Context) -> str:
    """Shape a pattern; a pattern that does not compile before or after shaping is replaced.

    The replacement is a filler pattern of the same length, not the original (I4 and I6 both
    forbid sending the original). Counts from a failed attempt are rolled back first.
    """
    kept, replaced = ctx.kept, ctx.replaced
    shaped = _shape_regex_body(text, ctx) if _regex_compiles(text) else None
    if shaped is not None and _regex_compiles(shaped):
        return shaped
    ctx.kept, ctx.replaced = kept, replaced
    ctx.fallbacks += 1
    ctx.replace(len(text))
    return _filler(text)


# ---- path --------------------------------------------------------------------------------------

_DRIVE: Final = re.compile(r"^[A-Za-z]:")
_LEADING: Final = re.compile(r"^(\.\./|\./|~/|/|\\)+")
_EXTENSION: Final = re.compile(r"^[A-Za-z0-9]{1,8}$")


def _shape_path(text: str, ctx: _Context) -> str:
    prefix = ""
    rest = text
    drive = _DRIVE.match(rest)
    if drive:
        prefix = drive.group(0)
        rest = rest[2:]
    leading = _LEADING.match(rest)
    if leading:
        prefix += leading.group(0)
        rest = rest[leading.end() :]
    ctx.keep()
    parts = re.split(r"([/\\])", rest)
    out = [prefix]
    for position, part in enumerate(parts):
        if position % 2 == 1:
            out.append(part)
            ctx.keep()
            continue
        out.append(_shape_path_segment(part, ctx))
    return "".join(out)


def _shape_path_segment(segment: str, ctx: _Context) -> str:
    if segment in ("", ".", "..") or ctx.is_kept_word(segment):
        ctx.keep()
        return segment
    stem, dot, extension = segment.rpartition(".")
    if dot and stem and _EXTENSION.match(extension) and not ctx.is_kept_word(stem):
        ctx.replace()
        return ctx.pseudonym(PseudonymKind.FILE, stem) + "." + extension
    if dot and stem and _EXTENSION.match(extension):
        ctx.keep()
        return segment
    ctx.replace()
    return ctx.pseudonym(PseudonymKind.FILE, segment)


# ---- url ---------------------------------------------------------------------------------------

_URL: Final = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://"
    r"(?:(?P<userinfo>[^@/?#]*)@)?"
    r"(?P<host>[^/?#:]*)"
    r"(?P<port>:\d+)?"
    r"(?P<path>/[^?#]*)?"
    r"(?:\?(?P<query>[^#]*))?"
    r"(?:#(?P<fragment>.*))?$",
    re.DOTALL,
)


def _shape_url_host(host: str, ctx: _Context) -> str:
    if _TEMPLATE_SEGMENT.match(host) or ctx.is_kept_word(host):
        ctx.keep()
        return host
    ctx.replace()
    return ctx.pseudonym(PseudonymKind.MOD, host)


def _shape_url_path(path: str, ctx: _Context) -> str:
    shaped_segments = []
    for segment in path.split("/"):
        if segment == "" or _TEMPLATE_SEGMENT.match(segment) or ctx.is_kept_word(segment):
            ctx.keep()
            shaped_segments.append(segment)
        else:
            ctx.replace()
            shaped_segments.append(ctx.pseudonym(PseudonymKind.VAR, segment))
    return "/".join(shaped_segments)


def _shape_url_query(query: str, ctx: _Context) -> str:
    pairs = []
    for pair in query.split("&"):
        name, equals, value = pair.partition("=")
        if name == "" or ctx.allowlist.is_public(name):
            ctx.keep()
            shaped_name = name
        else:
            ctx.replace()
            shaped_name = ctx.pseudonym(PseudonymKind.VAR, name)
        if equals and value:
            ctx.replace()
            pairs.append(f"{shaped_name}={FILLER}")
        elif equals:
            pairs.append(f"{shaped_name}=")
        else:
            pairs.append(shaped_name)
    return "&".join(pairs)


def _shape_url(text: str, ctx: _Context) -> str:
    match = _URL.match(text)
    if match is None:
        return _shape_natural(text, ctx)
    out = [match.group("scheme"), "://"]
    ctx.keep(2)
    if match.group("userinfo") is not None:
        ctx.replace()
    if match.group("host"):
        out.append(_shape_url_host(match.group("host"), ctx))
    if match.group("port"):
        ctx.keep()
        out.append(match.group("port"))
    if match.group("path"):
        out.append(_shape_url_path(match.group("path"), ctx))
    if match.group("query") is not None:
        out.append("?" + _shape_url_query(match.group("query"), ctx))
    if match.group("fragment") is not None:
        ctx.replace()
        out.append("#" + FILLER)
    return "".join(out)


# ---- sql ---------------------------------------------------------------------------------------

SQL_KEYWORDS: Final = frozenset(
    {
        "ADD", "ALL", "ALTER", "AND", "ANY", "AS", "ASC", "AVG", "BETWEEN", "BY", "CASE", "CAST",
        "CHAR", "COALESCE", "COLUMN", "COUNT", "CREATE", "CROSS", "DELETE", "DESC", "DISTINCT",
        "DROP", "ELSE", "END", "EXISTS", "FALSE", "FROM", "FULL", "GROUP", "HAVING", "IN", "INDEX",
        "INNER", "INSERT", "INT", "INTEGER", "INTO", "IS", "JOIN", "LEFT", "LIKE", "LIMIT", "LOWER",
        "MAX", "MIN", "NOT", "NULL", "OFFSET", "ON", "OR", "ORDER", "OUTER", "RETURNING", "RIGHT",
        "SELECT", "SET", "SUM", "TABLE", "TEXT", "THEN", "TRUE", "UNION", "UPDATE", "UPPER",
        "VALUES", "VARCHAR", "WHEN", "WHERE", "WITH",
    }
)  # fmt: skip
_TABLE_CONTEXT: Final = frozenset({"FROM", "JOIN", "INTO", "UPDATE", "TABLE"})
_COLUMN_CONTEXT: Final = frozenset(
    {"SELECT", "WHERE", "AND", "OR", "ON", "SET", "BY", "HAVING", "RETURNING", "DISTINCT"}
)
_COMPARISON: Final = frozenset({"=", "<", ">", "<=", ">=", "<>", "!="})
_SQL_TOKEN: Final = re.compile(
    r"(?P<ws>\s+)"
    r"|(?P<comment>--[^\n]*)"
    r"|(?P<sqstr>'(?:[^']|'')*')"
    r"|(?P<qident>\"(?:[^\"]|\"\")*\"|`[^`]*`)"
    r"|(?P<fmt>%\([A-Za-z_]\w*\)[sdif]|%[sdifr])"
    r"|(?P<param>\?|\$\d+|:[A-Za-z_]\w*)"
    r"|(?P<num>\d+(?:\.\d+)?)"
    r"|(?P<word>[A-Za-z_]\w*)"
    r"|(?P<cmp><=|>=|<>|!=|=|<|>)"
    r"|(?P<other>.)",
    re.DOTALL,
)


@dataclass(slots=True)
class _SqlToken:
    kind: str
    text: str


def _sql_tokens(text: str) -> list[_SqlToken]:
    tokens: list[_SqlToken] = []
    for match in _SQL_TOKEN.finditer(text):
        group = match.lastgroup or "other"
        tokens.append(_SqlToken(group, match.group(0)))
    return tokens


def _next_significant(tokens: list[_SqlToken], index: int) -> _SqlToken | None:
    for token in tokens[index + 1 :]:
        if token.kind != "ws":
            return token
    return None


def _previous_significant(tokens: list[_SqlToken], index: int) -> tuple[int, _SqlToken] | None:
    for position in range(index - 1, -1, -1):
        if tokens[position].kind != "ws":
            return position, tokens[position]
    return None


def _sql_identifier(
    word: str, tokens: list[_SqlToken], index: int, context: str | None, ctx: _Context
) -> str:
    nxt = _next_significant(tokens, index)
    if context in _TABLE_CONTEXT or (nxt is not None and nxt.text == "("):
        kind, prefix = PseudonymKind.VAR, ctx.display.table_prefix
    elif context in _COLUMN_CONTEXT or (nxt is not None and nxt.text in _COMPARISON):
        kind, prefix = PseudonymKind.FIELD, ctx.display.column_prefix
    else:
        kind, prefix = PseudonymKind.VAR, ctx.display.table_prefix
    ctx.replace()
    return ctx.pseudonym(kind, word, prefix)


def _sql_number(tokens: list[_SqlToken], index: int, ctx: _Context) -> str:
    text = tokens[index].text
    previous = _previous_significant(tokens, index)
    number_context = NumberContext()
    if previous is not None and previous[1].text in _COMPARISON:
        name_index = _previous_significant(tokens, previous[0])
        name = name_index[1].text if name_index is not None else None
        number_context = NumberContext(site=NumberSite.COMPARISON, name=name)
    shaped = generalise_number(text, number_context)
    if shaped == text:
        ctx.keep()
    else:
        ctx.replace()
    return shaped


def _sql_string(text: str, ctx: _Context) -> str:
    inner = text[1:-1]
    out: list[str] = []
    position = 0
    for match in _FORMAT_MARKER.finditer(inner):
        out.append(_fill_words(inner[position : match.start()], ctx))
        ctx.keep()
        out.append(match.group(0))
        position = match.end()
    out.append(_fill_words(inner[position:], ctx))
    return "'" + "".join(out) + "'"


def _sql_word(
    word: str, tokens: list[_SqlToken], index: int, context: str | None, ctx: _Context
) -> tuple[str, str | None]:
    """A bare word: a keyword or a kept word stays, anything else is a pseudonym.

    Returns the shaped word and the table or column context the next identifier is in.
    """
    upper = word.upper()
    if upper in SQL_KEYWORDS:
        ctx.keep()
        if upper in _TABLE_CONTEXT or upper in _COLUMN_CONTEXT:
            return word, upper
        return word, context
    if ctx.is_kept_word(word):
        ctx.keep()
        return word, context
    return _sql_identifier(word, tokens, index, context, ctx), context


def _sql_quoted(
    text: str, tokens: list[_SqlToken], index: int, context: str | None, ctx: _Context
) -> str:
    """A quoted identifier, re-wrapped in the quote characters it arrived with."""
    quote, inner = text[0], text[1:-1]
    if ctx.is_kept_word(inner):
        ctx.keep()
        return text
    return quote + _sql_identifier(inner, tokens, index, context, ctx) + quote


def _shape_sql(text: str, ctx: _Context) -> str:
    tokens = _sql_tokens(text)
    out: list[str] = []
    context: str | None = None
    for index, token in enumerate(tokens):
        kind = token.kind
        if kind == "comment":
            out.append(_fill_words(token.text, ctx))
        elif kind == "sqstr":
            out.append(_sql_string(token.text, ctx))
        elif kind == "qident":
            out.append(_sql_quoted(token.text, tokens, index, context, ctx))
        elif kind in ("fmt", "param"):
            ctx.keep()
            out.append(token.text)
        elif kind == "num":
            out.append(_sql_number(tokens, index, ctx))
        elif kind == "word":
            shaped_word, context = _sql_word(token.text, tokens, index, context, ctx)
            out.append(shaped_word)
        else:
            out.append(token.text)
    return "".join(out)


# ---- dispatch ----------------------------------------------------------------------------------

_SHAPERS: Final[dict[str, Callable[[str, _Context], str]]] = {
    "natural": _shape_natural,
    "format": _shape_format,
    "regex": _shape_regex,
    "path": _shape_path,
    "url": _shape_url,
    "sql": _shape_sql,
}


def _shape_content(text: str, kind: str, ctx: _Context) -> str:
    """Shape the content of one literal, placeholder tokens passed through untouched."""
    shaper = _SHAPERS[kind]
    out: list[str] = []
    position = 0
    for match in PLACEHOLDER_MASK_PATTERN.finditer(text):
        if match.start() > position:
            out.append(shaper(text[position : match.start()], ctx))
        out.append(match.group(0))
        ctx.keep()
        position = match.end()
    if position < len(text):
        out.append(shaper(text[position:], ctx))
    return "".join(out)


DEFAULT_DISPLAY: Final = ShapeDisplay()


def shape_content(
    content: str,
    kind: str,
    *,
    generator: PseudonymGenerator,
    allowlist: PublicAllowlist,
    display: ShapeDisplay = DEFAULT_DISPLAY,
) -> tuple[str, ShapeProvenance]:
    """Shape the content of a literal of ``kind``, returning the shaped text and its provenance.

    Raises:
        PseudonymError: ``kind`` is not one of the six literal kinds (fail closed).
    """
    if kind not in _SHAPERS:
        raise PseudonymError("an unknown literal kind cannot be shaped")
    ctx = _Context(generator=generator, allowlist=allowlist, display=display)
    shaped = _shape_content(content, kind, ctx)
    return shaped, ShapeProvenance(
        kind=kind,
        tokens_kept=ctx.kept,
        tokens_replaced=ctx.replaced,
        fallbacks=ctx.fallbacks,
    )


def shape(
    span: "LiteralSpan",
    *,
    generator: PseudonymGenerator,
    allowlist: PublicAllowlist,
    level: PrivacyLevel,
    display: ShapeDisplay = DEFAULT_DISPLAY,
) -> str:
    """The shaped content of ``span``, dispatched on ``span.kind``.

    The level is required so the caller's decision is explicit. At L0 nothing may be sent, so
    shaping is refused. From L1 upward the shaper is safe to run; the caller decides whether to
    invoke it at L1 (E09 runs it from L2).

    Raises:
        PseudonymError: the level is L0, or the kind is unknown.
    """
    if level is PrivacyLevel.L0:
        raise PseudonymError("nothing is sent at L0, so no literal is shaped")
    shaped, _ = shape_content(
        span.raw_text,
        str(span.kind),
        generator=generator,
        allowlist=allowlist,
        display=display,
    )
    return shaped


def shaped_provenance(
    span: "LiteralSpan",
    *,
    generator: PseudonymGenerator,
    allowlist: PublicAllowlist,
    display: ShapeDisplay = DEFAULT_DISPLAY,
) -> ShapeProvenance:
    """The provenance of shaping ``span``, without returning the shaped text."""
    _, provenance = shape_content(
        span.raw_text,
        str(span.kind),
        generator=generator,
        allowlist=allowlist,
        display=display,
    )
    return provenance
