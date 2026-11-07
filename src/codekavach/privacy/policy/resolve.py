"""The privacy policy resolver: which level applies to a path, and whether it may be sent at all.

Owning epic: E13. MVP; extended by E25, which adds policy-as-code files, per-repository overrides
and the policy explanation shown by ``privacy inspect``.

**Precedence** (decision D-A, strictness order ``L1 < L2 < L3 < L4 < L0``):

1. A ``never_send`` rule, in ``privacy.never_send`` or in a ``privacy.paths`` rule with
   ``never_send = true``, overrides everything: the path produces no payload at any level.
2. Otherwise the effective level is the **strictest** of the global ``privacy.level``, the level of
   the **most specific** matching ``privacy.paths`` rule, and the level the provider's trust tier
   demands, and it is never weaker than ``privacy.min_level``.

A path rule can therefore only tighten the global level, and a permissive local tier cannot loosen
it: ``min_level`` and the tier level are floors, not targets. "Most specific" is the rule with the
most literal path segments, then the most segments in all; between two equally specific rules the
later one wins (the order the configuration documents).

Patterns: one without ``/`` matches a file or directory of that name at any depth; one with ``/``
is anchored at the project root. ``*`` and ``?`` stay inside one segment, ``**`` spans segments,
and a pattern that matches a directory also matches everything below it.
"""

import fnmatch
from dataclasses import dataclass
from typing import Final

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel, RepoPath
from codekavach.core.models.enums import TrustTier

_WILDCARDS: Final = frozenset("*?[")


def _segments_match(pattern: list[str], parts: list[str]) -> bool:
    if not pattern:
        return not parts
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        return any(_segments_match(rest, parts[skip:]) for skip in range(len(parts) + 1))
    if not parts:
        return False
    return fnmatch.fnmatchcase(parts[0], head) and _segments_match(rest, parts[1:])


@dataclass(frozen=True, slots=True)
class _Compiled:
    """A glob split into segments, with the data needed to rank it."""

    segments: tuple[str, ...]
    anchored: bool

    @classmethod
    def of(cls, pattern: str) -> "_Compiled":
        trimmed = pattern.strip("/")
        return cls(tuple(trimmed.split("/")), "/" in trimmed)

    def matches(self, path: str) -> bool:
        parts = path.split("/")
        pattern = list(self.segments)
        starts = [0] if self.anchored else range(len(parts))
        return any(
            _segments_match(pattern, parts[start:end])
            for start in starts
            for end in range(start + 1, len(parts) + 1)
        )

    @property
    def specificity(self) -> tuple[int, int]:
        """``(literal segments, segments)``: more literal segments are more specific."""
        literal = sum(1 for segment in self.segments if not _WILDCARDS & set(segment))
        return literal, len(self.segments)


class PolicyResolver:
    """Resolves the effective privacy level of a path under one set of settings."""

    __slots__ = ("_level_rules", "_never_send", "_settings")

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        privacy = settings.privacy
        patterns = [*privacy.never_send, *(r.pattern for r in privacy.paths if r.never_send)]
        self._never_send = tuple(_Compiled.of(pattern) for pattern in patterns)
        rules: list[tuple[_Compiled, PrivacyLevel, int]] = []
        for order, rule in enumerate(privacy.paths):
            if rule.level is not None:
                rules.append((_Compiled.of(rule.pattern), rule.level, order))
        self._level_rules = tuple(rules)

    def is_never_send(self, path: RepoPath | str) -> bool:
        """True when ``path`` is covered by a ``never_send`` rule and must produce no payload."""
        return any(rule.matches(str(path)) for rule in self._never_send)

    def rule_level(self, path: RepoPath | str) -> PrivacyLevel | None:
        """The level of the most specific ``privacy.paths`` rule that matches, or ``None``."""
        best: tuple[tuple[int, int], int, PrivacyLevel] | None = None
        for compiled, level, order in self._level_rules:
            if compiled.matches(str(path)):
                candidate = (compiled.specificity, order, level)
                if best is None or candidate[:2] > best[:2]:
                    best = candidate
        return None if best is None else best[2]

    def effective_level(self, path: RepoPath | str, provider_tier: TrustTier) -> PrivacyLevel:
        """The level that applies to ``path`` when sent to a provider of ``provider_tier``.

        This does not consult ``never_send``: a caller asks ``is_never_send`` first and produces no
        payload for such a path, so that no level can be mistaken for permission to send.
        """
        privacy = self._settings.privacy
        rule = self.rule_level(path)
        return PrivacyLevel.strictest(
            privacy.level,
            privacy.floor_for_tier(provider_tier),
            *(() if rule is None else (rule,)),
        )
