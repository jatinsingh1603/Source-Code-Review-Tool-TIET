"""The validated shape of a project privacy policy, ``codekavach.policy.toml``.

Owning epic: E25.

A project policy is untrusted input (it lives in the scanned repository, ``docs/ARCHITECTURE.md``
section 6.4), so it may only tighten: ``codekavach.privacy.policy.loader`` refuses any level weaker
than ``privacy.min_level`` (``[CK-POL-006]``) instead of clamping it. Document format (TOML)::

    policy_version = 1
    [[path]]  # pattern + level, or pattern + never_send = true
    pattern = "src/payments/**"
    level = "L4"
    [[language]]
    language = "java"
    level = "L3"
    [[rule]]  # glob over rule ids and CWE ids
    match = "CWE-89"
    level = "L2"
    [[classification]]  # a data-classification tag: where it applies and what it demands
    tag = "pci"
    patterns = ["**/card/**"]
    level = "L4"
    [provider_tiers]
    public = "L3"

The document is RAW-classified: it carries client paths and patterns. Only ``content_hash()`` and
path-free rule keys may be recorded outside the client environment (E25-03).
"""

from __future__ import annotations

from typing import ClassVar, Literal

from pydantic import Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel
from codekavach.core.models.canonical import canonical_json, sha256_hex
from codekavach.core.models.enums import PrivacyLevel, TrustTier
from codekavach.privacy.policy.globs import check_pattern

_TAG = r"^[A-Za-z0-9_-]{1,64}$"
MAX_RULES = 1000


def _pattern(value: str) -> str:
    check_pattern(value)
    return value


class _Rule(KavachModel):
    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW


class PathPolicyRule(_Rule):
    """A glob with either a level or ``never_send``."""

    pattern: str  # validated by check_pattern: [CK-POL-004] rather than a generic error
    level: PrivacyLevel | None = None
    never_send: bool = False

    @field_validator("pattern")
    @classmethod
    def _check_pattern(cls, value: str) -> str:
        return _pattern(value)

    @model_validator(mode="after")
    def _one(self) -> PathPolicyRule:
        if (self.level is not None) == self.never_send:
            raise ValueError("a path rule sets exactly one of level or never_send")
        return self


class LanguagePolicyRule(_Rule):
    """A minimum level for every file of one language."""

    language: str = Field(min_length=1, max_length=64)
    level: PrivacyLevel


class RulePolicyRule(_Rule):
    """A minimum level for candidates whose rule id or CWE matches the glob."""

    match: str = Field(min_length=1, max_length=256)
    level: PrivacyLevel


class ClassificationRule(_Rule):
    """A data-classification tag attached to paths, with the level it demands."""

    tag: str = Field(pattern=_TAG)
    patterns: tuple[str, ...] = Field(min_length=1)
    level: PrivacyLevel | None = None
    never_send: bool = False

    @field_validator("patterns")
    @classmethod
    def _check_patterns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_pattern(p) for p in value)

    @model_validator(mode="after")
    def _demands(self) -> ClassificationRule:
        if self.level is None and not self.never_send:
            raise ValueError("a classification tag sets a level or never_send")
        return self


class PolicyDocument(_Rule):
    """A validated ``codekavach.policy.toml``."""

    policy_version: Literal[1] = 1
    path: tuple[PathPolicyRule, ...] = ()
    language: tuple[LanguagePolicyRule, ...] = ()
    rule: tuple[RulePolicyRule, ...] = ()
    classification: tuple[ClassificationRule, ...] = ()
    provider_tiers: dict[TrustTier, PrivacyLevel] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _bounded(self) -> PolicyDocument:
        if self.rule_count() > MAX_RULES:
            raise ValueError(f"more than {MAX_RULES} rules")
        return self

    def rule_count(self) -> int:
        """The number of rules over every axis."""
        return sum(self.rules_per_axis().values())

    def rules_per_axis(self) -> dict[str, int]:
        """Counts only: safe for the scan manifest (no pattern, tag or path)."""
        return {
            "path": len(self.path),
            "language": len(self.language),
            "rule": len(self.rule),
            "classification": len(self.classification),
            "provider_tiers": len(self.provider_tiers),
        }

    def levels(self) -> tuple[tuple[str, PrivacyLevel], ...]:
        """Every level the document states, with the TOML location that states it."""
        out: list[tuple[str, PrivacyLevel]] = []
        for i, p in enumerate(self.path):
            if p.level is not None:
                out.append((f"path[{i}]", p.level))
        out.extend((f"language[{i}]", r.level) for i, r in enumerate(self.language))
        out.extend((f"rule[{i}]", r.level) for i, r in enumerate(self.rule))
        for i, c in enumerate(self.classification):
            if c.level is not None:
                out.append((f"classification[{i}]", c.level))
        out.extend((f"provider_tiers.{t.value}", lv) for t, lv in self.provider_tiers.items())
        return tuple(out)

    def content_hash(self) -> str:
        """64 lower-case hex over the canonical JSON of the document."""
        return sha256_hex(canonical_json(self))
