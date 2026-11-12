"""The policy engine: path, language, rule and classification axes, strictest wins (E25-01).

Owning epic: E25.

A ``codekavach.policy.toml`` document (``codekavach.privacy.policy.model``) adds rules on top of the
settings that the loader already froze (``privacy.level``, ``privacy.min_level``, ``privacy.paths``,
``privacy.never_send`` and the organisation policy). Every axis contributes a level, the
contributions are combined with ``PrivacyLevel.strictest`` and nothing in a document can lower the
result: a document can only tighten, and ``codekavach.privacy.policy.loader`` refuses a level weaker
than ``privacy.min_level``. A ``never_send`` match overrides every level.

The engine is built once per scan (``for_scan``) and never reloaded while the scan runs, so one
document and one hash govern a whole run. Decisions are memoised per engine instance under a lock,
so the concurrent analyse and prepare waves see exactly the decisions a serial run would.

``PolicyDecision.rule_key`` and ``policy_hash`` are path-free and safe to record outside the client
environment; ``contributions`` carry the patterns and are shown to the operator only.
"""

from __future__ import annotations

import fnmatch
import threading
from collections.abc import Sequence
from pathlib import Path

from codekavach.config import Settings
from codekavach.core.models import PrivacyLevel
from codekavach.core.models.canonical import canonical_json, sha256_hex
from codekavach.core.models.enums import TrustTier
from codekavach.privacy.policy.decision import (
    RULE_KEY_PATTERN,
    Contribution,
    DecisionAxis,
    PolicyDecision,
)
from codekavach.privacy.policy.errors import PolicyError, PolicyErrorCode
from codekavach.privacy.policy.globs import GlobMatcher
from codekavach.privacy.policy.loader import (
    MAX_DOCUMENT_BYTES,
    POLICY_FILE,
    check_floor,
    load_document,
    load_policy,
)
from codekavach.privacy.policy.model import (
    ClassificationRule,
    LanguagePolicyRule,
    PathPolicyRule,
    PolicyDocument,
    RulePolicyRule,
)
from codekavach.privacy.policy.resolve import PolicyResolver

__all__ = [
    "MAX_DOCUMENT_BYTES",
    "POLICY_FILE",
    "RULE_KEY_PATTERN",
    "ClassificationRule",
    "Contribution",
    "DecisionAxis",
    "LanguagePolicyRule",
    "PathPolicyRule",
    "PolicyDecision",
    "PolicyDocument",
    "PolicyEngine",
    "PolicyError",
    "PolicyErrorCode",
    "RulePolicyRule",
    "load_document",
]

_MAX_CACHE = 50_000

_CacheKey = tuple[str, TrustTier, str | None, str | None, tuple[str, ...]]


def _settings_digest(settings: Settings) -> str:
    """The policy-relevant part of the settings, hashed: levels, tiers, paths, never-send."""
    privacy = settings.privacy
    payload = {
        "level": privacy.level.value,
        "min_level": privacy.min_level.value,
        "tiers": {t.value: lv.value for t, lv in sorted(privacy.provider_tier_levels.items())},
        "paths": [
            [r.pattern, None if r.level is None else r.level.value, r.never_send]
            for r in privacy.paths
        ],
        "never_send": list(privacy.never_send),
    }
    return sha256_hex(canonical_json(payload))


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
        self._document_hash = policy_hash or self._doc.content_hash()
        # The recorded hash binds the document to the settings it tightens, so a change to either
        # changes the hash an auditor sees in the ledger.
        self._hash = sha256_hex(
            canonical_json(
                {"document": self._document_hash, "settings": _settings_digest(settings)}
            )
        )
        self._paths = GlobMatcher(r.pattern for r in self._doc.path)
        self._classes = tuple(GlobMatcher(c.patterns) for c in self._doc.classification)
        self._cache: dict[_CacheKey, PolicyDecision] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_file(cls, settings: Settings, path: Path) -> PolicyEngine:
        """An engine for the document at ``path``; the floor check applies."""
        document, digest = load_document(path)
        text = path.read_text(encoding="utf-8")
        check_floor(document, settings, text, path.name)
        return cls(settings, document, digest)

    @classmethod
    def for_scan(cls, settings: Settings, *, project_root: Path) -> PolicyEngine:
        """The one construction point of a scan: the project's policy file, or settings only.

        Raises:
            PolicyError: the policy file is refused; the run must not proceed (I4).
        """
        loaded = load_policy(settings, project_root=project_root)
        return cls(settings) if loaded is None else cls(settings, *loaded)

    @classmethod
    def discover(cls, settings: Settings, root: Path) -> PolicyEngine:
        """Alias of ``for_scan`` kept for the M1 callers."""
        return cls.for_scan(settings, project_root=root)

    @property
    def policy_hash(self) -> str:
        """Hash of the document together with the policy-relevant settings."""
        return self._hash

    @property
    def document_hash(self) -> str:
        """Content hash of the policy file (or of the empty document)."""
        return self._document_hash

    @property
    def document(self) -> PolicyDocument:
        """The policy document (RAW: patterns and tags)."""
        return self._doc

    def manifest_entry(self) -> dict[str, object]:
        """What the scan manifest records: hashes and rule counts, never patterns or tags."""
        return {
            "policy_hash": self._hash,
            "document_hash": self._document_hash,
            "rules": self._doc.rules_per_axis(),
        }

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
        key: _CacheKey = (str(path), tier, language, rule_id, tuple(cwes))
        with self._lock:
            hit = self._cache.get(key)
        if hit is None:
            hit = self._resolve(str(path), tier, language, rule_id, tuple(cwes))
            with self._lock:
                if len(self._cache) < _MAX_CACHE:
                    self._cache[key] = hit
        return hit

    def resolve_many(
        self,
        paths: Sequence[str],
        tier: TrustTier,
        *,
        language: str | None = None,
        rule_id: str | None = None,
        cwes: tuple[str, ...] = (),
    ) -> tuple[PolicyDecision, ...]:
        """``resolve`` for each path, in order."""
        return tuple(
            self.resolve(p, tier, language=language, rule_id=rule_id, cwes=cwes) for p in paths
        )

    def resolve_candidate(
        self,
        paths: Sequence[str],
        tier: TrustTier,
        *,
        language: str | None = None,
        rule_id: str | None = None,
        cwes: tuple[str, ...] = (),
    ) -> PolicyDecision:
        """The strictest decision over every distinct file a candidate touches.

        If any file is never-send, the fold is never-send and the candidate is not prepared.
        """
        distinct = tuple(dict.fromkeys(str(p) for p in paths))
        return PolicyDecision.fold(
            self.resolve_many(distinct, tier, language=language, rule_id=rule_id, cwes=cwes)
        )

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
            Contribution(DecisionAxis.BASE, "", base, "privacy.level and privacy.min_level"),
            Contribution(
                DecisionAxis.PROVIDER_TIER,
                tier.value,
                privacy.floor_for_tier(tier),
                f"trust tier {tier.value}",
            ),
        ]
        doc_tier = self._doc.provider_tiers.get(tier)
        if doc_tier is not None:
            parts.append(
                Contribution(
                    DecisionAxis.PROVIDER_TIER, f"doc_{tier.value}", doc_tier, "policy file"
                )
            )
        if self._base.is_never_send(path):
            parts.append(
                Contribution(DecisionAxis.NEVER_SEND, "settings", None, "privacy.never_send")
            )
        rule_level = self._base.rule_level(path)
        if rule_level is not None:
            parts.append(
                Contribution(DecisionAxis.SETTINGS_PATH, "paths", rule_level, "privacy.paths")
            )
        for index in self._paths.matches(path):
            rule = self._doc.path[index]
            if rule.never_send:
                parts.append(
                    Contribution(DecisionAxis.NEVER_SEND, f"path_rule{index}", None, rule.pattern)
                )
            else:
                parts.append(
                    Contribution(DecisionAxis.PATH_RULE, str(index), rule.level, rule.pattern)
                )
        tags: list[str] = []
        for crule, globs in zip(self._doc.classification, self._classes, strict=True):
            if not globs.any(path):
                continue
            tags.append(crule.tag)
            if crule.never_send:
                parts.append(
                    Contribution(DecisionAxis.NEVER_SEND, f"class_{crule.tag}", None, crule.tag)
                )
            if crule.level is not None:
                parts.append(
                    Contribution(DecisionAxis.CLASSIFICATION, crule.tag, crule.level, crule.tag)
                )
        if language and language.lower() != "unknown":
            for index, lrule in enumerate(self._doc.language):
                if lrule.language.lower() == language.lower():
                    parts.append(
                        Contribution(DecisionAxis.LANGUAGE, str(index), lrule.level, language)
                    )
        wanted = [x for x in (rule_id, *cwes) if x]
        for index, rrule in enumerate(self._doc.rule):
            if any(fnmatch.fnmatchcase(w.lower(), rrule.match.lower()) for w in wanted):
                parts.append(Contribution(DecisionAxis.RULE, str(index), rrule.level, rrule.match))
        levels = [p.level for p in parts if p.level is not None]
        return PolicyDecision(
            level=PrivacyLevel.strictest(*levels),
            never_send=any(p.axis is DecisionAxis.NEVER_SEND for p in parts),
            classifications=tuple(dict.fromkeys(tags)),
            contributions=tuple(parts),
            policy_hash=self._hash,
        )
