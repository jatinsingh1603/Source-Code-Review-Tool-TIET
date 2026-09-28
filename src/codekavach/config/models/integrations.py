"""The ``[integrations]`` section: GitHub sync and the MCP server (E34 and E35 implement).

Owning epic: E03.

Every integration writes vulnerability details to a remote system, so the defaults are inert:
nothing is enabled and ``dry_run`` starts as true. The whole section is restricted in untrusted
project configuration (E03-25), because whoever controls the target repository, API host or token
receives the client's findings. Tokens are secret references only (ADR decision D4). There is no
auto-fix or pull-request vocabulary: the project never modifies client code.
"""

import re
from typing import Annotated, Literal, Self

from pydantic import AnyHttpUrl, Field, field_validator, model_validator

from codekavach.config.keys import SecretRef
from codekavach.config.models.base import INVALID, SectionModel, bounds, in_range
from codekavach.config.models.llm import is_loopback_host
from codekavach.core.models import Severity

PREREQUISITE = "[CK-CFG-036]"
BAD_URL = "[CK-CFG-034]"
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
_LABELS_PREFIX = re.compile(r"^[a-z0-9-]{1,30}$")


class GitHubSettings(SectionModel):
    """Issue sync, Projects v2 sync, SARIF upload and check runs on GitHub."""

    enabled: bool = Field(default=False, description="Master switch of the GitHub integration.")
    repository: str | None = Field(
        default=None, description="Target repository written as owner/name."
    )
    api_url: AnyHttpUrl = Field(
        default=AnyHttpUrl("https://api.github.com"),
        description="API base URL; GitHub Enterprise Server is allowed, https only.",
    )
    token: SecretRef | None = Field(
        default=None,
        description="Secret reference to the token; env:GITHUB_TOKEN or env:GH_TOKEN when unset.",
    )
    dry_run: bool = Field(default=True, description="Log intended writes without performing them.")
    issue_sync: bool = Field(default=False, description="Raise one issue per finding.")
    close_resolved: bool = Field(
        default=True, description="Close issues whose finding no longer appears."
    )
    min_severity_for_issues: Severity = Field(
        default=Severity.MEDIUM, description="Lowest severity for which an issue is raised."
    )
    max_issues_per_run: Annotated[
        int, in_range(1, 500, "integrations.github.max_issues_per_run")
    ] = Field(
        default=50,
        description="Largest number of issues created or updated in one run.",
        json_schema_extra=bounds(1, 500),
    )
    labels_prefix: str = Field(
        default="codekavach", description="Prefix of the labels the integration applies."
    )
    project_owner: str | None = Field(
        default=None, description="Organisation or user that owns the Projects v2 board."
    )
    project_number: int | None = Field(
        default=None, ge=1, description="Number of the Projects v2 board."
    )
    sarif_upload: bool = Field(default=False, description="Upload SARIF to code scanning.")
    checks: bool = Field(default=False, description="Create check runs and annotations.")

    @field_validator("repository")
    @classmethod
    def _check_repository(cls, value: str | None) -> str | None:
        if value is not None and not _REPOSITORY.match(value):
            raise ValueError(f"{INVALID} integrations.github.repository must be owner/name")
        return value

    @field_validator("labels_prefix")
    @classmethod
    def _check_labels_prefix(cls, value: str) -> str:
        if not _LABELS_PREFIX.match(value):
            raise ValueError(
                f"{INVALID} integrations.github.labels_prefix must be 1 to 30 of a-z, 0-9 and -"
            )
        return value

    @field_validator("api_url")
    @classmethod
    def _check_api_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        host = value.host or "unknown host"
        if value.username is not None or value.password is not None:
            raise ValueError(f"{BAD_URL} integrations.github.api_url for {host} holds credentials")
        if value.scheme != "https":
            raise ValueError(f"{BAD_URL} integrations.github.api_url for {host} must use https")
        return value

    @model_validator(mode="after")
    def _check_prerequisites(self) -> Self:
        writes = self.issue_sync or self.sarif_upload or self.checks
        if (writes or self.project_number is not None) and not (self.enabled and self.repository):
            raise ValueError(
                f"{PREREQUISITE} integrations.github features need enabled = true and a repository"
            )
        if self.project_number is not None and not self.project_owner:
            raise ValueError(
                f"{PREREQUISITE} integrations.github.project_number needs project_owner"
            )
        return self


class McpSettings(SectionModel):
    """The MCP server that exposes CodeKavach to editors and agents."""

    enabled: bool = Field(default=False, description="Start the MCP server.")
    transport: Literal["stdio", "http"] = Field(
        default="stdio", description="Transport of the MCP server."
    )
    bind: str = Field(
        default="127.0.0.1:8765", description="Host and port the HTTP transport listens on."
    )
    allow_non_loopback: bool = Field(
        default=False,
        description="Allow the HTTP transport to listen on a non-loopback address.",
    )

    @model_validator(mode="after")
    def _check_bind(self) -> Self:
        host, separator, port = self.bind.rpartition(":")
        if not separator or not port.isdigit() or not 1 <= int(port) <= 65535 or not host:
            raise ValueError(f"{INVALID} integrations.mcp.bind must be host:port")
        if not is_loopback_host(host) and not (
            self.transport == "http" and self.allow_non_loopback
        ):
            raise ValueError(
                f"{INVALID} integrations.mcp.bind must be a loopback address unless the http "
                "transport sets allow_non_loopback"
            )
        return self


class IntegrationsSettings(SectionModel):
    """External systems that receive findings."""

    github: GitHubSettings = Field(
        default_factory=GitHubSettings, description="GitHub issue, board, SARIF and check sync."
    )
    mcp: McpSettings = Field(default_factory=McpSettings, description="The MCP server.")
