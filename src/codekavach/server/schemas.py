"""Request bodies of the REST API (Pydantic v2).

Owning epic: E32.

Responses are plain JSON objects documented in ``docs/api.md``; request bodies are validated here
so a malformed request is refused with 422 and a ``validation_error`` code before a handler runs.
"""

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

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
    # Quick review: the model reviews only the N most severe candidates (0 = all; unset = the
    # provider's default, 8 for agentrouter). The rest keep their deterministic evidence.
    review_limit: int | None = Field(default=None, ge=0, le=100_000)


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
    # Trimmed; a blank name left the sidebar and the reports without an organisation.
    org_name: (
        Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
        | None
    ) = None
    report_title: str | None = Field(default=None, max_length=200)
    classification: str | None = Field(default=None, max_length=64)
    send_by_default: bool | None = None
    provider_key_refs: dict[str, str] | None = None


class ProviderTestBody(BaseModel):
    """``POST /providers/{id}/test`` (optional)."""

    model_config = ConfigDict(extra="ignore")

    model: str | None = Field(default=None, max_length=128)


class PolicyBody(_Body):
    """``PUT /policy``."""

    toml: str = Field(max_length=200_000)


# Empty (not set) or one plausible address; the server sends no mail, so this only catches typos.
EMAIL_PATTERN: Final = r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$"


class UserCreate(_Body):
    """``POST /users``."""

    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: RoleName = "viewer"
    full_name: str = Field(default="", max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    email: str = Field(default="", max_length=256, pattern=EMAIL_PATTERN)


class UserUpdate(_Body):
    """``PATCH /users/{id}``."""

    password: str | None = Field(default=None, min_length=8, max_length=256)
    role: RoleName | None = None
    full_name: str | None = Field(default=None, max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=256, pattern=EMAIL_PATTERN)
    active: bool | None = None


class GithubSyncBody(_Body):
    """``POST /scans/{id}/sync/github``."""

    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    token_ref: str | None = Field(default=None, max_length=256)
    dry_run: bool = True
    finding_ids: list[str] | None = Field(default=None, max_length=500)


class ViewCreate(_Body):
    """``POST /views``: a named set of findings filters."""

    name: str = Field(min_length=1, max_length=128)
    filters: dict[str, str | None] = Field(default_factory=dict)


class TokenCreate(_Body):
    """``POST /me/tokens``: a personal API token."""

    name: str = Field(min_length=1, max_length=128)
    expires_in_days: int | None = Field(default=90, ge=1, le=730)


class ProfileUpdate(_Body):
    """``PATCH /me``: the caller's own name and e-mail address."""

    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=256, pattern=EMAIL_PATTERN)


class PasswordChange(_Body):
    """``POST /me/password``: the caller's own password, confirmed with the current one."""

    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


class PreferencesBody(BaseModel):
    """``PATCH /me/preferences``: display preferences (unknown keys are refused)."""

    model_config = ConfigDict(extra="forbid")

    theme: Literal["light", "dark", "system"] | None = None
    density: Literal["comfortable", "compact"] | None = None
    reduce_motion: bool | None = None
    language: str | None = Field(default=None, max_length=16, pattern=r"^[a-z]{2}(-[A-Z]{2})?$")
    time_zone: str | None = Field(default=None, max_length=64)
    date_format: Literal["long", "iso"] | None = None


class NotificationsBody(BaseModel):
    """``PATCH /me/notifications``: event to channel switches (stored only, nothing is sent)."""

    model_config = ConfigDict(extra="forbid")

    events: dict[str, dict[str, bool]] = Field(default_factory=dict)


class PolicyValidateBody(_Body):
    """``POST /policy/validate``."""

    toml: str = Field(max_length=200_000)
    project_id: str | None = Field(default=None, max_length=64)


class RoleBody(_Body):
    """``PUT /users/{id}/role``."""

    role: RoleName


class EvaluationRunBody(_Body):
    """``POST /evaluation/run``."""

    levels: list[LevelName] | None = Field(default=None, max_length=5)
    limit: int | None = Field(default=None, ge=1, le=10_000)
