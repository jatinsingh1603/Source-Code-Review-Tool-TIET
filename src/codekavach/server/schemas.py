"""Request bodies of the REST API (Pydantic v2).

Owning epic: E32.

Responses are plain JSON objects documented in ``docs/api.md``; request bodies are validated here
so a malformed request is refused with 422 and a ``validation_error`` code before a handler runs.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RoleName = Literal["admin", "auditor", "developer", "viewer"]
LevelName = Literal["L0", "L1", "L2", "L3", "L4"]
StatusName = Literal["open", "confirmed", "false_positive", "accepted_risk", "fixed"]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginBody(_Body):
    """``POST /auth/login``."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class SourceBody(_Body):
    """Where a project's code comes from."""

    type: Literal["path", "git", "upload", "sample"]
    path: str | None = Field(default=None, max_length=4096)
    url: str | None = Field(default=None, max_length=2048)
    ref: str | None = Field(default=None, max_length=256)


class ProjectCreate(_Body):
    """``POST /projects``."""

    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=4000)
    source: SourceBody


class ProjectUpdate(_Body):
    """``PATCH /projects/{id}``."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=4000)
    source: SourceBody | None = None


class ScanCreate(_Body):
    """``POST /projects/{id}/scans``."""

    privacy_level: LevelName | None = None
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    send: bool | None = None
    rules: list[str] | None = None


class FindingPatch(_Body):
    """``PATCH /findings/{id}``."""

    status: StatusName | None = None
    comment: str | None = Field(default=None, max_length=4000)
    assignee: str | None = Field(default=None, max_length=64)


class SettingsBody(BaseModel):
    """``PUT /settings`` (unknown keys are ignored)."""

    model_config = ConfigDict(extra="ignore")

    default_provider: str | None = None
    default_model: str | None = None
    default_privacy_level: LevelName | None = None
    org_name: str | None = Field(default=None, max_length=200)
    report_title: str | None = Field(default=None, max_length=200)
    classification: str | None = Field(default=None, max_length=64)
    send_by_default: bool | None = None


class PolicyBody(_Body):
    """``PUT /policy``."""

    toml: str = Field(max_length=200_000)


class UserCreate(_Body):
    """``POST /users``."""

    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: RoleName = "viewer"
    full_name: str = Field(default="", max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    email: str = Field(default="", max_length=256)


class UserUpdate(_Body):
    """``PATCH /users/{id}``."""

    password: str | None = Field(default=None, min_length=8, max_length=256)
    role: RoleName | None = None
    full_name: str | None = Field(default=None, max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=256)
    active: bool | None = None


class GithubSyncBody(_Body):
    """``POST /scans/{id}/sync/github``."""

    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    token_ref: str | None = Field(default=None, max_length=256)
    dry_run: bool = True
