"""Repository-path globs of the privacy policy, translated to linear regular expressions.

Owning epic: E25.

Patterns are repository-relative and use ``/``. ``*`` matches within one segment and never crosses
``/``; ``?`` matches one character other than ``/``; a ``**`` segment matches zero or more whole
segments; a pattern without ``/`` matches a file or directory of that name at any depth. Every
other character, regular-expression metacharacters included, is literal, and matching is
case-sensitive.

A pattern that matches a directory also matches everything below it, so ``src/payments`` and
``src/payments/**`` cover the same files. This keeps the M1 resolver's semantics: every policy rule
can only tighten (a stricter level or never-send), so matching more paths is the fail-safe
direction, and an operator who omits the trailing ``/**`` is not silently left uncovered.

The translation is linear: a run of ``**`` segments collapses into one ``(?:[^/]+/)*`` and patterns
carry at most ``MAX_WILDCARDS`` wildcards, so a pathological pattern cannot cause catastrophic
backtracking (CWE-1333).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

from codekavach.privacy.policy.errors import PolicyError, PolicyErrorCode

MAX_PATTERN_LENGTH: Final = 256
MAX_WILDCARDS: Final = 16
_DRIVE: Final = re.compile(r"^[A-Za-z]:")


def check_pattern(pattern: str) -> str:
    """Return ``pattern`` when it is a valid policy glob, else raise ``[CK-POL-004]``."""
    bad = PolicyErrorCode.BAD_PATTERN
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        raise PolicyError(bad, f"patterns are 1 to {MAX_PATTERN_LENGTH} characters", pattern=None)
    if "\\" in pattern or "\x00" in pattern:
        raise PolicyError(bad, f"pattern {pattern!r} must use / and no NUL", pattern=pattern)
    if pattern.startswith("/") or _DRIVE.match(pattern):
        raise PolicyError(bad, f"pattern {pattern!r} must be relative", pattern=pattern)
    if ".." in pattern.split("/"):
        raise PolicyError(bad, f"pattern {pattern!r} has a .. segment", pattern=pattern)
    if pattern.count("*") + pattern.count("?") > MAX_WILDCARDS:
        raise PolicyError(bad, f"pattern {pattern!r} has too many wildcards", pattern=pattern)
    return pattern


def _segment(text: str) -> str:
    out: list[str] = []
    for char in text:
        if char == "*":
            if not out or out[-1] != "[^/]*":  # a run of * is one *, which keeps it linear
                out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(char))
    return "".join(out)


def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Translate a validated glob into an anchored regular expression."""
    check_pattern(pattern)
    trimmed = pattern.strip("/")
    segments = [s for s in trimmed.split("/") if s]
    while segments and segments[-1] == "**":
        segments.pop()  # a trailing /** is the directory itself: covered by the suffix below
    if not segments:
        return re.compile(r"\A.*\Z", re.DOTALL)
    parts: list[str] = []
    if "/" not in trimmed:
        parts.append("(?:[^/]+/)*")
    previous_any = False
    for index, segment in enumerate(segments):
        if segment == "**":
            if not previous_any:
                parts.append("(?:[^/]+/)*")
            previous_any = True
            continue
        previous_any = False
        parts.append(_segment(segment))
        if index < len(segments) - 1:
            parts.append("/")
    return re.compile(r"\A" + "".join(parts) + r"(?:/.*)?\Z", re.DOTALL)


class GlobMatcher:
    """Compiled patterns in declaration order."""

    __slots__ = ("_compiled", "patterns")

    def __init__(self, patterns: Iterable[str]) -> None:
        self.patterns = tuple(patterns)
        self._compiled = tuple(compile_pattern(p) for p in self.patterns)

    def __len__(self) -> int:
        return len(self._compiled)

    def matches(self, path: str) -> tuple[int, ...]:
        """The indices of the patterns that match ``path``, in declaration order."""
        text = str(path).strip("/")
        return tuple(i for i, rx in enumerate(self._compiled) if rx.match(text))

    def any(self, path: str) -> bool:
        """True when at least one pattern matches ``path``."""
        text = str(path).strip("/")
        return any(rx.match(text) for rx in self._compiled)
