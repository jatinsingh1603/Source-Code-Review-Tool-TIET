"""The ``[privacy]`` section: how much may leave the machine.

Owning epic: E03.

Defaults give level L3 (requirement R2). The policy engine (E25) resolves levels per path and per
provider tier; this section only states the configuration it reads.

Deliberate omissions (ADR decision D8): there is no key that disables redaction, the egress
guard, the ledger or fail-closed behaviour, and none may be added without a new ADR. The least
strict configuration expressible is ``level = "L1"``. Consent for remote egress is not a setting
either (a scanned repository's own configuration could set it); it is per-user state, a flag or a
process variable owned by E05-13.
"""

import re
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from codekavach.config.keys import SecretRef
from codekavach.config.models.base import (
    INVALID,
    PrivacyLevelField,
    SectionModel,
    StrList,
    restricted,
    sensitive,
    union_merge,
)
from codekavach.core.models import PrivacyLevel, TrustTier

FLOOR_VIOLATION = "[CK-CFG-037]"
BAD_RULE = "[CK-CFG-039]"
MISSING_FIELD = "[CK-CFG-033]"
MAX_PATH_RULES = 500
MAX_PATTERN_LENGTH = 256
DEFAULT_TIER_LEVELS: dict[TrustTier, PrivacyLevel] = {
    TrustTier.LOCAL: PrivacyLevel.L1,
    TrustTier.PRIVATE: PrivacyLevel.L2,
    TrustTier.PUBLIC: PrivacyLevel.L3,
}
DEFAULT_NEVER_SEND = [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/id_rsa*",
    "**/id_ed25519*",
]
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{1,63}$")
_DRIVE = re.compile(r"^[A-Za-z]:")


def check_pattern(key: str, pattern: str) -> str:
    """Validate a path glob: relative, ``/`` separators, no ``..`` segment, 1 to 256 chars."""
    if not pattern or len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(f"{BAD_RULE} {key} patterns must be 1 to {MAX_PATTERN_LENGTH} characters")
    if "\\" in pattern or "\x00" in pattern:
        raise ValueError(f"{BAD_RULE} {key} patterns use / separators and contain no NUL")
    if pattern.startswith("/") or _DRIVE.match(pattern):
        raise ValueError(f"{BAD_RULE} {key} patterns must be relative to the project root")
    if ".." in pattern.split("/"):
        raise ValueError(f"{BAD_RULE} {key} patterns must not contain a .. segment")
    return pattern


class PathRule(SectionModel):
    """A per-path privacy rule; later rules win on overlap (evaluated by E25)."""

    pattern: str = Field(description="Glob relative to the project root.")
    level: PrivacyLevelField | None = Field(
        default=None, description="Privacy level for matching files."
    )
    never_send: bool = Field(
        default=False, description="Never prepare matching files for egress at any level."
    )

    @field_validator("pattern")
    @classmethod
    def _check_pattern(cls, value: str) -> str:
        return check_pattern("privacy.paths", value)

    @model_validator(mode="after")
    def _one_action(self) -> Self:
        if (self.level is not None) == self.never_send:
            raise ValueError(f"{BAD_RULE} a path rule sets exactly one of level or never_send")
        return self


class VaultSettings(SectionModel):
    """Where the mapping vault's key comes from (E10 implements)."""

    key_source: Literal["keyring", "passphrase", "kms"] = Field(
        default="keyring",
        description="Source of the vault key: OS keyring, passphrase or key-management service.",
        json_schema_extra=restricted(),
    )
    passphrase: SecretRef | None = Field(
        default=None,
        description="Secret reference to the passphrase; required when key_source is passphrase.",
        json_schema_extra=restricted(),
    )

    @model_validator(mode="after")
    def _passphrase_present(self) -> Self:
        if self.key_source == "passphrase" and self.passphrase is None:
            raise ValueError(f"{MISSING_FIELD} privacy.vault.passphrase is required")
        return self


class PrivacySettings(SectionModel):
    """What may leave the machine, at which privacy level."""

    level: PrivacyLevelField = Field(
        default=PrivacyLevel.L3, description="Default privacy level for every path."
    )
    min_level: PrivacyLevelField = Field(
        default=PrivacyLevel.L1,
        description="Floor that no configured level may be weaker than.",
    )
    provider_tier_levels: dict[TrustTier, PrivacyLevelField] = Field(
        default_factory=lambda: dict(DEFAULT_TIER_LEVELS),
        description="Minimum privacy level per provider trust tier.",
    )
    paths: list[PathRule] = Field(
        default_factory=list,
        max_length=MAX_PATH_RULES,
        description="Per-path rules; later rules win on overlap.",
    )
    never_send: StrList = Field(
        default_factory=lambda: list(DEFAULT_NEVER_SEND),
        description="Globs whose content is never prepared for egress at any level.",
        json_schema_extra=union_merge(),
    )
    domain_terms: StrList = Field(
        default_factory=list,
        description="Business words that must not appear verbatim in any payload.",
        json_schema_extra=union_merge() | sensitive(),
    )
    domain_terms_file: Path | None = Field(
        default=None,
        description="File with one domain term per line; lines starting with # are comments.",
    )
    public_allowlist_extra: StrList = Field(
        default_factory=list,
        description="Extra identifiers kept un-pseudonymised; every entry weakens privacy.",
        json_schema_extra=restricted(),
    )
    vault: VaultSettings = Field(
        default_factory=VaultSettings, description="Where the vault key comes from."
    )

    @field_validator("provider_tier_levels", mode="before")
    @classmethod
    def _complete_tiers(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {**{tier.value: level for tier, level in DEFAULT_TIER_LEVELS.items()}, **value}
        return value

    @field_validator("never_send")
    @classmethod
    def _check_never_send(cls, value: list[str]) -> list[str]:
        return [check_pattern("privacy.never_send", pattern) for pattern in value]

    @field_validator("public_allowlist_extra")
    @classmethod
    def _check_identifiers(cls, value: list[str]) -> list[str]:
        for name in value:
            if not _IDENTIFIER.match(name):
                raise ValueError(
                    f"{INVALID} privacy.public_allowlist_extra entries must be identifiers"
                )
        return value

    @model_validator(mode="after")
    def _check_floor(self) -> Self:
        if not self.level.at_least(self.min_level):
            raise ValueError(f"{FLOOR_VIOLATION} privacy.level is weaker than privacy.min_level")
        for index, rule in enumerate(self.paths):
            if rule.level is not None and not rule.level.at_least(self.min_level):
                raise ValueError(
                    f"{FLOOR_VIOLATION} privacy.paths[{index}].level is weaker than "
                    "privacy.min_level"
                )
        return self

    def floor_for_tier(self, tier: TrustTier) -> PrivacyLevel:
        """The stricter of ``min_level`` and the configured level for ``tier``."""
        return PrivacyLevel.strictest(self.min_level, self.provider_tier_levels[tier])
