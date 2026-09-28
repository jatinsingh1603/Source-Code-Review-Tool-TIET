"""The organisation policy file format (``policy.toml``, ADR decision D7, E03-28).

Owning epic: E03.

Every rule is optional: ``None`` means "no constraint". ``lock`` pins dotted settings keys to a
value; each key must name a settings field, checked against the ``Settings`` model at load time.
Enforcement is E03-29; this module only describes and validates the file.
"""

import difflib
from datetime import date
from typing import Literal

from pydantic import Field, field_validator

from codekavach.config.introspect import iter_fields, resolve_field
from codekavach.config.models.base import PrivacyLevelField, SectionModel, StrList
from codekavach.config.models.llm import ProviderKind
from codekavach.config.models.root import Settings
from codekavach.core.models import TrustTier

POLICY_VERSION = 1
BAD_POLICY = "[CK-CFG-050]"

LockValue = str | int | float | bool | list[str | int | float | bool]


class PrivacyRules(SectionModel):
    """Privacy floors that bind every layer, the operator's included."""

    min_level: PrivacyLevelField | None = Field(
        default=None, description="Floor for privacy.level, every path rule and every tier."
    )
    min_level_by_tier: dict[TrustTier, PrivacyLevelField] | None = Field(
        default=None, description="Floor per provider trust tier."
    )
    never_send: StrList | None = Field(
        default=None, description="Globs added to privacy.never_send in every run."
    )
    forbid_allowlist_extra: bool | None = Field(
        default=None, description="True forbids privacy.public_allowlist_extra entirely."
    )


class LlmRules(SectionModel):
    """Which providers may be used."""

    allow_remote: bool | None = Field(
        default=None, description="False forbids every remote provider."
    )
    allowed_kinds: list[ProviderKind] | None = Field(
        default=None, description="Provider kinds that may be configured."
    )
    allowed_providers: list[str] | None = Field(
        default=None, description="Provider ids that may be used; empty means any id."
    )
    allowed_base_url_hosts: list[str] | None = Field(
        default=None, description="Hosts that provider base URLs may point at."
    )


class IntegrationRules(SectionModel):
    """Which external systems may receive findings."""

    allow_github: bool | None = Field(
        default=None, description="False forbids the GitHub integration."
    )
    allowed_github_api_hosts: list[str] | None = Field(
        default=None, description="Hosts that integrations.github.api_url may point at."
    )


class ProjectConfigRules(SectionModel):
    """How far project configuration files may be trusted."""

    allow_trust: bool | None = Field(
        default=None,
        description="False ignores --trust-project-config, the variable and the trust store.",
    )


class OrgPolicy(SectionModel):
    """One organisation policy file."""

    policy_version: Literal[1] = Field(description="Format version of the policy file.")
    organisation: str = Field(
        min_length=1, max_length=200, description="Name of the issuing organisation."
    )
    enforcement: Literal["reject", "clamp"] = Field(
        default="reject",
        description="reject stops a run that violates the policy; clamp tightens and warns.",
    )
    issued: date | None = Field(default=None, description="Date the policy was issued.")
    expires: date | None = Field(
        default=None, description="Date after which the policy no longer loads."
    )
    privacy: PrivacyRules = Field(default_factory=PrivacyRules, description="Privacy floors.")
    llm: LlmRules = Field(default_factory=LlmRules, description="Provider rules.")
    integrations: IntegrationRules = Field(
        default_factory=IntegrationRules, description="Integration rules."
    )
    project_config: ProjectConfigRules = Field(
        default_factory=ProjectConfigRules, description="Project configuration trust rules."
    )
    lock: dict[str, LockValue] = Field(
        default_factory=dict, description="Settings keys pinned to a value in every run."
    )

    @field_validator("lock")
    @classmethod
    def _known_keys(cls, value: dict[str, LockValue]) -> dict[str, LockValue]:
        known = [ref.key for ref in iter_fields(Settings)]
        for key in value:
            if resolve_field(Settings, key) is None:
                close = difflib.get_close_matches(key, known, n=1)
                hint = f"; did you mean '{close[0]}'?" if close else ""
                raise ValueError(f"{BAD_POLICY} lock names an unknown settings key '{key}'{hint}")
        return value
