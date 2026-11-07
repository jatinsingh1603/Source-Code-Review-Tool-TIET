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
from typing import Annotated, Any, Final, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from codekavach.config.keys import SecretRef
from codekavach.config.models.base import (
    INVALID,
    PrivacyLevelField,
    SectionModel,
    StrList,
    bounds,
    float_in_range,
    in_range,
    restricted,
    sensitive,
    union_merge,
)
from codekavach.core.models import Confidence, PrivacyLevel, TrustTier

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
_LOCALE = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
# The personal-data locales (E08-03): ``intl`` and ``in`` enable a format set, ``passport`` opts in
# to the conservative passport-number detector. An entry outside this list is a load-time error.
PII_LOCALES: Final = ("intl", "in", "passport")
_DRIVE = re.compile(r"^[A-Za-z]:")
# A host name or address, or ``*.`` and a domain of at least two labels: ``*`` and ``*.com`` would
# turn the allow-list into a formality.
_ALLOWED_HOST = re.compile(
    r"^(?:\*\.[A-Za-z0-9-]+\.[A-Za-z0-9.-]+|[A-Za-z0-9:][A-Za-z0-9.:-]{0,252})$"
)


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
    retention_days: Annotated[int, in_range(1, 36_500, "privacy.vault.retention_days")] | None = (
        Field(
            default=None,
            description=(
                "Days after which a scan's mappings may be removed from the vault; unset keeps "
                "them. Not enforced yet: retention is applied by the vault tooling of E10-03."
            ),
            json_schema_extra=bounds(1, 36_500) | restricted(),
        )
    )

    @model_validator(mode="after")
    def _passphrase_present(self) -> Self:
        if self.key_source == "passphrase" and self.passphrase is None:
            raise ValueError(f"{MISSING_FIELD} privacy.vault.passphrase is required")
        return self


class DetectSettings(SectionModel):
    """How the secret, PII and domain-term detectors run (E08)."""

    min_confidence: Confidence = Field(
        default=Confidence.LOW,
        description=(
            "Lowest detector confidence that is redacted. Low by default: a false positive "
            "costs a placeholder, a false negative leaks a credential."
        ),
        json_schema_extra=restricted(),
    )


class EgressSettings(SectionModel):
    """Limits the egress guard applies to every request (E12).

    Every key bounds a check; none switches one off. The numeric keys have a lower bound above
    zero so that no value can mean "unlimited", and the guard's scanners are registered in code
    with no key that names them. The whole section is restricted: a scanned repository must not
    be able to add a host or relax a budget for itself.
    """

    max_payload_bytes: Annotated[
        int, in_range(1_024, 16_777_216, "privacy.egress.max_payload_bytes")
    ] = Field(
        default=262_144,
        description="Largest serialised request body the guard lets out, in bytes.",
        json_schema_extra=bounds(1_024, 16_777_216) | restricted(),
    )
    aggregation_budget_pct: Annotated[
        float, float_in_range(0.1, 100.0, "privacy.egress.aggregation_budget_pct")
    ] = Field(
        default=100.0,
        description="Share of a repository that may be disclosed across one scan, in percent.",
        json_schema_extra={"minimum": 0.1, "maximum": 100.0} | restricted(),
    )
    rate_per_minute: Annotated[int, in_range(1, 100_000, "privacy.egress.rate_per_minute")] = Field(
        default=60,
        description="Most requests the guard lets out in any one minute.",
        json_schema_extra=bounds(1, 100_000) | restricted(),
    )
    provider_host_allowlist: StrList = Field(
        default_factory=list,
        description=(
            "Hosts a remote provider may be reached on (exact, or *.example.com for subdomains). "
            "Empty allows no remote host."
        ),
        json_schema_extra=restricted(),
    )
    encrypt_at_rest: bool = Field(
        default=True,
        description="Encrypt the stored payloads of the egress ledger.",
        json_schema_extra=restricted(),
    )
    ticket_ttl_seconds: Annotated[int, in_range(1, 3_600, "privacy.egress.ticket_ttl_seconds")] = (
        Field(
            default=60,
            description="How long an egress ticket stays valid, in seconds.",
            json_schema_extra=bounds(1, 3_600) | restricted(),
        )
    )
    scanner_timeout_seconds: Annotated[
        float, float_in_range(0.05, 60.0, "privacy.egress.scanner_timeout_seconds")
    ] = Field(
        default=5.0,
        description="Time limit of one leak scanner; a scanner over it blocks the request.",
        json_schema_extra={"minimum": 0.05, "maximum": 60.0} | restricted(),
    )

    proxy_url: str | None = Field(
        default=None,
        description=(
            "An explicit proxy for remote providers: an http or https address with host and "
            "port. Ambient proxy environment variables are never read. A proxy is a party in "
            "the path: name what it may do in proxy_trust. Credentials are not accepted."
        ),
        json_schema_extra=restricted(),
    )
    proxy_trust: Literal["none", "inspect", "terminate"] = Field(
        default="none",
        description=(
            "What the proxy may do: none tunnels the TLS connection and sees only the host; "
            "inspect and terminate declare that it can see requests, which the privacy "
            "attestation records."
        ),
        json_schema_extra=restricted(),
    )

    @field_validator("proxy_url")
    @classmethod
    def _check_proxy(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = urlsplit(value)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
        ):
            raise ValueError(
                f"{INVALID} privacy.egress.proxy_url is an http or https address with a host "
                "and no credentials, path or query"
            )
        return value

    @field_validator("provider_host_allowlist")
    @classmethod
    def _check_hosts(cls, value: list[str]) -> list[str]:
        for host in value:
            if not _ALLOWED_HOST.match(host):
                raise ValueError(
                    f"{INVALID} privacy.egress.provider_host_allowlist entries are host names "
                    "or *.example.com"
                )
        return value


class PseudonymSettings(SectionModel):
    """How identifiers are renamed (E09)."""

    link_mode: Literal["per_scan", "per_request"] = Field(
        default="per_scan",
        description=(
            "per_scan keeps one name for an identifier across a scan; per_request renames it "
            "afresh in every request, which defeats the verdict cache and cross-slice reasoning."
        ),
    )
    role_hints: bool = Field(
        default=False,
        description=(
            "Append an analysis-derived role (cred, authz, sanitised, tainted, sink_arg) to a "
            "pseudonym. Leave off in a client engagement until the leakage arm has measured it."
        ),
        json_schema_extra=restricted(),
    )


class SliceSettings(SectionModel):
    """How much code is cut out around a candidate (E11).

    Both keys are restricted: a larger budget or a wider strategy discloses more code, so a
    project file may not loosen them unless it is trusted.
    """

    default_strategy: Literal["enclosing_function", "taint_path", "backward_slice"] = Field(
        default="enclosing_function",
        description=(
            "Slice strategy used when nothing more specific applies. The path-based strategies "
            "need a taint engine and fall back to the enclosing function without one."
        ),
        json_schema_extra=restricted(),
    )
    max_tokens: Annotated[int, in_range(64, 200_000, "privacy.slice.max_tokens")] = Field(
        default=2048,
        description=(
            "Token budget of one slice, estimated locally (about 3.5 characters per token). "
            "A slice that cannot fit is shrunk in a fixed order and, failing that, refused."
        ),
        json_schema_extra=bounds(64, 200_000) | restricted(),
    )


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
    pii_locales: StrList = Field(
        default_factory=lambda: ["intl", "in"],
        description="Personal-data locales to detect: intl, in, passport (E08-03).",
        json_schema_extra=restricted(),
    )
    detect: DetectSettings = Field(
        default_factory=DetectSettings, description="How the redaction detectors run."
    )
    vault: VaultSettings = Field(
        default_factory=VaultSettings, description="Where the vault key comes from."
    )
    egress: EgressSettings = Field(
        default_factory=EgressSettings, description="Limits the egress guard applies."
    )
    pseudonym: PseudonymSettings = Field(
        default_factory=PseudonymSettings, description="How identifiers are renamed."
    )
    slice: SliceSettings = Field(
        default_factory=SliceSettings, description="How much code is cut out around a candidate."
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

    @field_validator("pii_locales")
    @classmethod
    def _check_locales(cls, value: list[str]) -> list[str]:
        for locale in value:
            if not _LOCALE.match(locale):
                raise ValueError(f"{INVALID} privacy.pii_locales entries must be locale names")
            if locale not in PII_LOCALES:
                raise ValueError(
                    f"{INVALID} privacy.pii_locales has an unknown locale; "
                    f"the known locales are {', '.join(PII_LOCALES)}"
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
