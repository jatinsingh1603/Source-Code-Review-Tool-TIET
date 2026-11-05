"""``safe_compile``: compile a pattern only if it cannot backtrack catastrophically.

Owning epic: E08.

Every regular expression in the detection epic goes through :func:`safe_compile`, at import time.
It rejects the classic super-linear shape, an **unbounded repeat inside an unbounded repeat**
such as ``(a+)+``, ``(a*)*``, ``(?:x+y?)*`` or ``(.*a)+`` (CWE-1333, ``docs/research/INSIGHTS.md``
section 7). A detector runs per candidate and again in the egress guard on text the scanned
repository controls, so a pattern that a crafted file can drive to exponential time would let a
repository stall or hide from the scan.

This is a structural check on the parsed pattern, not a proof of linear time: it does not catch
every ambiguous construct (for instance an alternation whose branches overlap inside a repeat).
It is the cheap guard that stops the common mistake; the corpus and the performance budget are
the other two.
"""

import importlib
import re
from typing import Any, Final

_PARSER: Any = importlib.import_module("re._parser")
_UNBOUNDED: Final[int] = _PARSER.MAXREPEAT
_REPEATS: Final = frozenset({_PARSER.MAX_REPEAT, _PARSER.MIN_REPEAT})


class UnsafePattern(ValueError):  # noqa: N818 - a pattern is "unsafe", not an "error" of a kind
    """A pattern with nested unbounded quantifiers."""


def _children(op: Any, argument: Any) -> list[Any]:
    """The sub-patterns of one parsed item, for the ops that have any."""
    children: list[Any] = []
    if op in _REPEATS:
        children = [argument[2]]
    elif op == _PARSER.SUBPATTERN:
        children = [argument[3]]
    elif op == _PARSER.BRANCH:
        children = list(argument[1])
    elif op in (_PARSER.ASSERT, _PARSER.ASSERT_NOT):
        children = [argument[1]]
    elif op == _PARSER.ATOMIC_GROUP:
        children = [argument]
    elif op == _PARSER.GROUPREF_EXISTS:
        children = [part for part in argument[1:] if part is not None]
    return children


def _contains_unbounded(pattern: Any) -> bool:
    for op, argument in pattern:
        if op in _REPEATS and argument[1] == _UNBOUNDED:
            return True
        if any(_contains_unbounded(child) for child in _children(op, argument)):
            return True
    return False


def _has_nested_unbounded(pattern: Any) -> bool:
    for op, argument in pattern:
        if op in _REPEATS and argument[1] == _UNBOUNDED and _contains_unbounded(argument[2]):
            return True
        if any(_has_nested_unbounded(child) for child in _children(op, argument)):
            return True
    return False


def safe_compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Compile ``pattern``, or raise :class:`UnsafePattern` when it nests unbounded repeats.

    Raises:
        UnsafePattern: an unbounded quantifier (``*``, ``+``, ``{n,}``) contains another one.
        re.error: the pattern is not valid.
    """
    parsed = _PARSER.parse(pattern, flags)
    if _has_nested_unbounded(parsed):
        raise UnsafePattern("the pattern nests unbounded quantifiers (super-linear matching)")
    return re.compile(pattern, flags)
