"""String-operation propagation and narrowing conversions, as data (E17-02).

Owning epic: E17. Taint propagates through every operation that builds a string from its operands:
concatenation, formatted string literals, ``format`` calls, percent formatting, ``join``, template
literals and replacement functions. The tables below say which, so adding an operation is a data
change with a reason, not a new branch.

*Narrowing.* A conversion to a number or a boolean cannot carry an injection payload into a query
or a command line, so it clears taint for the ``sql`` and ``shell`` contexts. It does not clear it
for ``path`` or ``url``: ``int(x)`` of ``"-1"`` still walks out of a directory in some APIs, and a
number still selects which resource a URL fetches. The rule is per context, which is why a cleared
value flows on and is only dropped at a sink of a cleared context.
"""

from dataclasses import dataclass
from typing import Final

from codekavach.analysis.taint.ir import Op

STRING_STYLES: Final[dict[str, str]] = {
    "concat": "concat",
    "fstring": "fstring",
    "format": "format",
    "template": "template",
}
"""Operator style of the IR to the operation name recorded on a step."""

OTHER_STYLES: Final[dict[str, str]] = {
    "binary": "arithmetic",
    "unary": "unary",
    "bool": "select",
    "collection": "collection",
}
"""Operations that carry their operands' taint without building a string. ``compare`` is absent
on purpose: a comparison yields a boolean."""

STRING_METHODS: Final[dict[str, str]] = {
    "format": "format",
    "format_map": "format",
    "join": "join",
    "replace": "replace",
    "replaceAll": "replace",
    "sub": "replace",
    "strip": "strip",
    "lstrip": "strip",
    "rstrip": "strip",
    "trim": "strip",
    "trimStart": "strip",
    "trimEnd": "strip",
    "lower": "case",
    "upper": "case",
    "title": "case",
    "capitalize": "case",
    "toLowerCase": "case",
    "toUpperCase": "case",
    "encode": "encode",
    "decode": "encode",
    "concat": "concat",
    "padStart": "pad",
    "padEnd": "pad",
    "ljust": "pad",
    "rjust": "pad",
    "repeat": "repeat",
    "substring": "slice",
    "substr": "slice",
    "slice": "slice",
    "split": "split",
    "splitlines": "split",
    "str": "convert",
    "String": "convert",
    "bytes": "convert",
    "bytearray": "convert",
    "toString": "convert",
    "dumps": "serialise",
    "stringify": "serialise",
}
"""Methods and conversions whose result is a string derived from the receiver and the arguments."""

READ_METHODS: Final[dict[str, str]] = {
    "get": "read",
    "getlist": "read",
    "pop": "read",
    "popitem": "read",
    "setdefault": "read",
    "items": "read",
    "values": "read",
    "keys": "read",
    "copy": "read",
    "__getitem__": "read",
    "getAll": "read",
    "getHeader": "read",
    "header": "read",
    "param": "read",
    "query": "read",
}
"""Container reads: the result holds what the receiver held."""


@dataclass(frozen=True, slots=True)
class Narrowing:
    """A conversion that clears taint for some contexts, with the reason it is safe there."""

    clears: frozenset[str]
    reason: str


_NUMERIC: Final = Narrowing(
    frozenset({"sql", "shell"}),
    "a number or a boolean cannot carry quotes or shell metacharacters",
)

NARROWING: Final[dict[str, Narrowing]] = {
    "int": _NUMERIC,
    "float": _NUMERIC,
    "bool": _NUMERIC,
    "len": _NUMERIC,
    "ord": _NUMERIC,
    "Number": _NUMERIC,
    "parseInt": _NUMERIC,
    "parseFloat": _NUMERIC,
    "Boolean": _NUMERIC,
    "isNaN": _NUMERIC,
}
"""Callee name (last segment, unqualified or ``builtins``/``globalThis``) to its narrowing."""


def operation_of(op: Op) -> str | None:
    """The step note for an operator node, or ``None`` when it carries no taint (a comparison)."""
    if op.style in STRING_STYLES:
        return STRING_STYLES[op.style]
    return OTHER_STYLES.get(op.style)


def last_segment(callee_text: str) -> str:
    """The method or function name of a callee: ``a.b.format`` is ``format``."""
    return callee_text.rsplit(".", 1)[-1].removeprefix("new ")
