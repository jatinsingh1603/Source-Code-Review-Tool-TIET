"""Numeric literal generalisation: keep the security-relevant values, coarsen the rest.

Owning epic: E09. Issue E09-03. Normative layout: docs/ARCHITECTURE.md section 3.

A number is kept verbatim only when it is security-relevant by name or by value, and only when it
sits in a position where that relevance is evident: a comparison, an argument to a public API, or
an assignment to a constant whose name says what it is. Everything else is replaced by the
representative of its magnitude class (``0``, ``1``, ``10``, ``100`` and the negative and
fractional equivalents), so the order of magnitude survives and the exact business figure does not.

The constants ``0`` and ``1`` are always kept. A value that cannot be parsed as a number is never
returned as it was: it is replaced by ``0`` (fail closed, invariant I4 in spirit).

Security-relevant categories, matched on the words of the name (split on ``_`` and camel case):
network ports, file permission modes, key and hash sizes, iteration and round counts, timeouts,
retry counts, HTTP status codes, buffer and length bounds used in a comparison, and array
indices below ``INDEX_KEEP_LIMIT``. A bare ``max`` or ``limit`` is not enough: ``max_price`` is
business data, so it does not qualify.
"""

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Final

INDEX_KEEP_LIMIT: Final = 16
_ZERO_ONE: Final = frozenset({Decimal(0), Decimal(1)})
_SPLIT: Final = re.compile(r"[_\s\-.]+|(?<=[a-z0-9])(?=[A-Z])")


class NumberSite(StrEnum):
    """Where a number occurs; only the first three can make a number security-relevant."""

    COMPARISON = "comparison"
    PUBLIC_ARGUMENT = "public_argument"
    CONSTANT_ASSIGNMENT = "constant_assignment"
    INDEX = "index"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class NumberContext:
    """The position of a number: its site and the name it is bound to, when there is one.

    ``name`` is the constant or variable the value is assigned to, the other operand's name in a
    comparison, or the callee's name for a public API argument. It is never shown in output.
    """

    site: NumberSite = NumberSite.OTHER
    name: str | None = None


_PORT = frozenset({"port"})
_MODE = frozenset({"mode", "perm", "perms", "permission", "permissions", "chmod", "umask"})
_KEY_SIZE_MARKS = frozenset({"bits", "keysize", "keylen"})
_KEY_WORDS = frozenset({"key", "hash", "digest"})
_SIZE_WORDS = frozenset({"size", "len", "length", "bits"})
_ITERATION = frozenset({"iteration", "iterations", "round", "rounds", "cost", "work"})
_TIMEOUT = frozenset({"timeout", "timeouts"})
_RETRY = frozenset({"retry", "retries", "attempt", "attempts"})
_STATUS = frozenset({"status"})
_BOUND = frozenset({"buf", "buffer", "length", "len", "bound", "bounds"})


def _words(name: str) -> frozenset[str]:
    return frozenset(part.lower() for part in _SPLIT.split(name) if part)


def _parse(value: str) -> Decimal | None:
    """The numeric value of a literal, or ``None`` when it is not a number this module knows."""
    text = value.replace("_", "").strip()
    if text[-1:] in ("l", "L", "u", "U", "f", "F") and not text.lower().startswith("0x"):
        text = text[:-1]
    try:
        if text.lower().startswith("0o"):
            return Decimal(int(text[2:], 8))
        if text.lower().startswith("0b"):
            return Decimal(int(text[2:], 2))
        if text.lower().startswith("0x"):
            return Decimal(int(text[2:], 16))
        number = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    return number if number.is_finite() else None


def _magnitude_representative(number: Decimal) -> str:
    """``0`` for zero, else ``1`` scaled to the power of ten of the value's magnitude."""
    if number == 0:
        return "0"
    exponent = number.copy_abs().adjusted()
    sign = "-" if number < 0 else ""
    return sign + format(Decimal(1).scaleb(exponent), "f")


def _is_integer(number: Decimal) -> bool:
    return number == number.to_integral_value()


def _is_security_relevant(value: str, number: Decimal, context: NumberContext) -> bool:
    """True when the value's position and name make it a security-relevant constant."""
    if context.site is NumberSite.INDEX:
        return _is_integer(number) and 0 <= number < INDEX_KEEP_LIMIT
    if context.site is NumberSite.OTHER:
        return False
    words = _words(context.name) if context.name else frozenset()
    if words & _MODE or value.lower().startswith("0o"):
        return context.site in (NumberSite.PUBLIC_ARGUMENT, NumberSite.CONSTANT_ASSIGNMENT)
    if words & _BOUND:
        return context.site is NumberSite.COMPARISON
    if words & _STATUS:
        return _is_integer(number) and 100 <= number <= 599
    named_kinds = (_PORT, _KEY_SIZE_MARKS, _ITERATION, _TIMEOUT, _RETRY)
    return any(words & kind for kind in named_kinds) or bool(
        words & _KEY_WORDS and words & _SIZE_WORDS
    )


def generalise_number(value: str, context: NumberContext) -> str:
    """Keep ``value`` when it is security-relevant in ``context``, else coarsen it.

    A coarsened value is the magnitude representative. ``0`` and ``1`` are always returned
    unchanged. A value that is not a parseable number is
    returned as ``"0"``, so no unparsed text can reach a payload.
    """
    number = _parse(value)
    if number is None:
        return "0"
    if number in _ZERO_ONE:
        return value
    if _is_security_relevant(value, number, context):
        return value
    return _magnitude_representative(number)
