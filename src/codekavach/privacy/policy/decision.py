"""A policy decision: the effective level of one file, with every contribution that led to it.

Owning epic: E25.

``PolicyDecision`` is RAW-classified: its contributions name patterns and the caller holds the
path, both client data. It is never serialised into a payload, a ledger entry or an integration
body; the static guard of invariant I2 lists it among the names forbidden inside
``codekavach.llm``. Only ``policy_hash`` and the path-free ``rule_key`` leave this module (E25-03).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Final

from codekavach.core.models.base import DataClassification
from codekavach.core.models.enums import PrivacyLevel

RULE_KEY_PATTERN: Final = re.compile(r"^[a-z_]+:[A-Za-z0-9_-]{0,64}$")


class DecisionAxis(StrEnum):
    """The axes of a decision, in the order they are recorded and break ties."""

    BASE = "base"
    PROVIDER_TIER = "provider_tier"
    SETTINGS_PATH = "settings_path"
    PATH_RULE = "path_rule"
    CLASSIFICATION = "classification"
    LANGUAGE = "language"
    RULE = "rule"
    NEVER_SEND = "never_send"


@dataclass(frozen=True, slots=True)
class Contribution:
    """One input to a decision. ``detail`` may name a pattern: operator-facing only."""

    axis: DecisionAxis
    key: str
    level: PrivacyLevel | None
    detail: str = ""

    @property
    def rule_key(self) -> str:
        """``<axis>:<key>``; contains no path."""
        return f"{self.axis.value}:{self.key}"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The effective level of one triple, or the fold over every file of a candidate."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    level: PrivacyLevel
    never_send: bool
    classifications: tuple[str, ...]
    contributions: tuple[Contribution, ...]
    policy_hash: str
    paths: int = 1

    @property
    def winner(self) -> Contribution:
        """The contribution that fixed the result: never_send first, else the strictest level.

        Ties go to the earliest contribution, so the explanation is stable.
        """
        for item in self.contributions:
            if item.axis is DecisionAxis.NEVER_SEND:
                return item
        best = self.contributions[0]
        for item in self.contributions:
            if item.level is not None and (best.level is None or item.level > best.level):
                best = item
        return best

    @property
    def rule_key(self) -> str:
        """Stable identifier of the winning contribution; free of paths and patterns."""
        key = self.winner.rule_key
        if not RULE_KEY_PATTERN.match(key):
            raise ValueError("rule key is not path-free")
        return key

    def explain(self, path: str | None = None) -> str:
        """Operator-facing text: the result, then every contribution, the winner marked ``*``.

        It names patterns and levels and never file contents.
        """
        verdict = "-> never sent" if self.never_send else f"level {self.level.value}"
        head = f"{path}: {verdict}" if path else verdict
        lines = [head, f"decided by {self.winner.axis.value} ({self.rule_key})"]
        winner = self.winner
        for item in self.contributions:
            mark = "*" if item is winner else " "
            level = item.level.value if item.level is not None else "never_send"
            lines.append(f" {mark} {item.axis.value:<14} {level:<10} {item.detail}".rstrip())
        if self.classifications:
            lines.append("classifications: " + ", ".join(self.classifications))
        if self.paths > 1:
            lines.append(f"files folded: {self.paths}")
        lines.append(f"policy hash {self.policy_hash}")
        return "\n".join(lines)

    @classmethod
    def fold(cls, decisions: tuple[PolicyDecision, ...]) -> PolicyDecision:
        """The strictest of several decisions, for a candidate that spans several files."""
        if not decisions:
            raise ValueError("a candidate touches at least one file")
        if len(decisions) == 1:
            return decisions[0]
        parts = tuple(dict.fromkeys(c for d in decisions for c in d.contributions))
        return cls(
            level=PrivacyLevel.strictest(*(d.level for d in decisions)),
            never_send=any(d.never_send for d in decisions),
            classifications=tuple(dict.fromkeys(t for d in decisions for t in d.classifications)),
            contributions=parts,
            policy_hash=decisions[0].policy_hash,
            paths=len(decisions),
        )
