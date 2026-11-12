"""The policy engine: path, language, rule and classification axes, strictest wins (E25-01).

A ``codekavach.policy.toml`` document adds rules on top of the settings that the loader already
froze (``privacy.level``, ``privacy.min_level``, ``privacy.paths``, ``privacy.never_send`` and the
organisation policy). Every axis contributes a level, the contributions are combined with
``PrivacyLevel.strictest`` and nothing in a document can lower the result: a document can only
tighten. A ``never_send`` match overrides every level.

Document format (TOML)::

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

``PolicyDecision.rule_key`` and ``policy_hash`` are path-free and safe to record outside the client
environment; ``contributions`` carry the patterns and are shown to the operator only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.policy.resolve import PolicyResolver, _Compiled

POLICY_FILE: Final = "codekavach.policy.toml"
MAX_DOCUMENT_BYTES: Final = 256 * 1024
RULE_KEY_PATTERN: Final = re.compile(r"^[a-z_]+:[A-Za-z0-9_-]{0,64}$")
_TAG: Final = r"^[A-Za-z0-9_-]{1,64}$"

Axis = Literal[
    "base",
    "settings_path",
    "path_rule",
    "language",
    "rule",
    "classification",
    "provider_tier",
    "never_send",
]


class PolicyError(Exception):
    """A policy document is unreadable or invalid. ``code`` is a stable identifier."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PathPolicyRule(_Model):
    """A glob with either a level or ``never_send``."""

    pattern: str = Field(min_length=1, max_length=512)
    level: PrivacyLevel | None = None
    never_send: bool = False

    @model_validator(mode="after")
    def _one(self) -> PathPolicyRule:
        if (self.level is not None) == self.never_send:
            raise ValueError("a path rule sets exactly one of level or never_send")
        return self


class LanguagePolicyRule(_Model):
    """A minimum level for every file of one language."""

    language: str = Field(min_length=1, max_length=64)
    level: PrivacyLevel


class RulePolicyRule(_Model):
    """A minimum level for candidates whose rule id or CWE matches the glob."""

    match: str = Field(min_length=1, max_length=256)
    level: PrivacyLevel


class ClassificationRule(_Model):
    """A data-classification tag attached to paths, with the level it demands."""

    tag: str = Field(pattern=_TAG)
    patterns: tuple[str, ...] = Field(min_length=1)
    level: PrivacyLevel | None = None
    never_send: bool = False


class PolicyDocument(_Model):
    """A validated ``codekavach.policy.toml``."""

    policy_version: Literal[1] = 1
    path: tuple[PathPolicyRule, ...] = ()
    language: tuple[LanguagePolicyRule, ...] = ()
    rule: tuple[RulePolicyRule, ...] = ()
    classification: tuple[ClassificationRule, ...] = ()
    provider_tiers: dict[TrustTier, PrivacyLevel] = Field(default_factory=dict)


def load_document(source: str | bytes | Path) -> tuple[PolicyDocument, str]:
    """Parse and validate a policy; returns the document and its content hash (sha256 hex)."""
    if isinstance(source, Path):
        raw = source.read_bytes()
    elif isinstance(source, str):
        raw = source.encode()
    else:
        raw = source
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise PolicyError("CK-POL-001", "policy document is too large")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
        return PolicyDocument.model_validate(data), hashlib.sha256(raw).hexdigest()
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError(
            "CK-POL-002", f"policy is not valid TOML ({type(exc).__name__})"
        ) from None
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise PolicyError("CK-POL-003", f"invalid policy at '{where}': {first['msg']}") from None


@dataclass(frozen=True, slots=True)
class Contribution:
    """One input to a decision. ``detail`` may name a pattern: operator-facing only."""

    axis: Axis
    key: str
    level: PrivacyLevel | None
    detail: str = ""

    @property
    def rule_key(self) -> str:
        """``<axis>:<key>``; contains no path."""
        return f"{self.axis}:{self.key}"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The effective level of one triple, with every contribution that led to it."""

    level: PrivacyLevel
    never_send: bool
    classifications: tuple[str, ...]
    contributions: tuple[Contribution, ...]
    policy_hash: str

    @property
    def winner(self) -> Contribution:
        """The contribution that fixed the result: never_send first, else the strictest level."""
        for item in self.contributions:
            if item.axis == "never_send":
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


_CacheKey = tuple[str, TrustTier, str | None, str | None, tuple[str, ...]]


class PolicyEngine:
    """Resolves the effective level of (path, provider tier, language, rule) triples."""

    def __init__(
        self,
        settings: Settings,
        document: PolicyDocument | None = None,
        policy_hash: str | None = None,
    ) -> None:
        self._settings = settings
        self._base = PolicyResolver(settings)
        self._doc = document or PolicyDocument()
        fallback = hashlib.sha256(self._doc.model_dump_json().encode()).hexdigest()
        self._hash = policy_hash or fallback
        self._paths = tuple(_Compiled.of(r.pattern) for r in self._doc.path)
        self._classes = tuple(
            tuple(_Compiled.of(p) for p in c.patterns) for c in self._doc.classification
        )
        self._cache: dict[_CacheKey, PolicyDecision] = {}

    @classmethod
    def from_file(cls, settings: Settings, path: Path) -> PolicyEngine:
        """An engine for the document at ``path``."""
        document, digest = load_document(path)
        return cls(settings, document, digest)

    @classmethod
    def discover(cls, settings: Settings, root: Path) -> PolicyEngine:
        """Use ``codekavach.policy.toml`` in ``root`` when present, else settings only."""
        file = root / POLICY_FILE
        return cls.from_file(settings, file) if file.is_file() else cls(settings)

    @property
    def policy_hash(self) -> str:
        """Content hash of the policy document (or of the empty document)."""
        return self._hash

    def is_never_send(self, path: str) -> bool:
        """True when ``path`` is never sent, whatever the provider."""
        return self.resolve(path, TrustTier.PUBLIC).never_send

    def resolve(
        self,
        path: str,
        tier: TrustTier,
        *,
        language: str | None = None,
        rule_id: str | None = None,
        cwes: tuple[str, ...] = (),
    ) -> PolicyDecision:
        """The decision for one (path, provider tier, language, rule) triple; cached."""
        key: _CacheKey = (str(path), tier, language, rule_id, cwes)
        hit = self._cache.get(key)
        if hit is None:
            hit = self._resolve(str(path), tier, language, rule_id, cwes)
            if len(self._cache) < 50_000:
                self._cache[key] = hit
        return hit

    def _resolve(  # noqa: PLR0912 - one block per axis
        self,
        path: str,
        tier: TrustTier,
        language: str | None,
        rule_id: str | None,
        cwes: tuple[str, ...],
    ) -> PolicyDecision:
        privacy = self._settings.privacy
        base = PrivacyLevel.strictest(privacy.level, privacy.min_level)
        parts: list[Contribution] = [
            Contribution("base", "", base, "privacy.level and privacy.min_level"),
            Contribution(
                "provider_tier",
                tier.value,
                privacy.floor_for_tier(tier),
                f"trust tier {tier.value}",
            ),
        ]
        doc_tier = self._doc.provider_tiers.get(tier)
        if doc_tier is not None:
            parts.append(
                Contribution("provider_tier", f"doc_{tier.value}", doc_tier, "policy file")
            )
        if self._base.is_never_send(path):
            parts.append(Contribution("never_send", "settings", None, "privacy.never_send"))
        rule_level = self._base.rule_level(path)
        if rule_level is not None:
            parts.append(Contribution("settings_path", "paths", rule_level, "privacy.paths"))
        for index, (rule, glob) in enumerate(zip(self._doc.path, self._paths, strict=True)):
            if not glob.matches(path):
                continue
            if rule.never_send:
                parts.append(Contribution("never_send", f"path_rule{index}", None, rule.pattern))
            else:
                parts.append(Contribution("path_rule", str(index), rule.level, rule.pattern))
        tags: list[str] = []
        for crule, globs in zip(self._doc.classification, self._classes, strict=True):
            if not any(g.matches(path) for g in globs):
                continue
            tags.append(crule.tag)
            if crule.never_send:
                parts.append(Contribution("never_send", f"class_{crule.tag}", None, crule.tag))
            if crule.level is not None:
                parts.append(Contribution("classification", crule.tag, crule.level, crule.tag))
        if language:
            for index, lrule in enumerate(self._doc.language):
                if lrule.language.lower() == language.lower():
                    parts.append(Contribution("language", str(index), lrule.level, language))
        wanted = [x for x in (rule_id, *cwes) if x]
        for index, rrule in enumerate(self._doc.rule):
            if any(fnmatch.fnmatchcase(w.lower(), rrule.match.lower()) for w in wanted):
                parts.append(Contribution("rule", str(index), rrule.level, rrule.match))
        levels = [p.level for p in parts if p.level is not None]
        return PolicyDecision(
            level=PrivacyLevel.strictest(*levels),
            never_send=any(p.axis == "never_send" for p in parts),
            classifications=tuple(dict.fromkeys(tags)),
            contributions=tuple(parts),
            policy_hash=self._hash,
        )
