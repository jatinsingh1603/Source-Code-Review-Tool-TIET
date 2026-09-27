"""Project, Scan and StageResult: the records of one pipeline run.

Owning epic: E02.

These are local records, but they are the objects most likely to appear in dashboards, issue
sync metadata or a pasted bug report. They therefore never hold the scan salt (the vault owns
it, E10), credentials (clone URLs with a token or password are rejected), API keys or free-form
exception text. They are classified raw because project names, local paths and branch names
identify the client.
"""

import re
import unicodedata
from datetime import datetime
from typing import Any, ClassVar, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.enums import Language, PrivacyLevel, ScanStatus, StageStatus
from codekavach.core.models.errors import ModelError
from codekavach.core.models.ids import ProjectId, ProjectIdField, ScanIdField, new_scan_id
from codekavach.core.models.summary import ScanSummary
from codekavach.core.models.timeutil import UtcDatetime

STAGE_NAME_PATTERN = r"^[a-z][a-z0-9-]{0,47}$"
ERROR_CODE_PATTERN = r"^[a-z][a-z0-9_]{1,63}$"
HEX64_PATTERN = r"^[0-9a-f]{64}$"
GIT_COMMIT_PATTERN = r"^[0-9a-f]{7,64}$"
DEFAULT_STAGES = (
    "ingest",
    "parse",
    "analyse",
    "aggregate",
    "privacy-prepare",
    "llm-review",
    "restore",
    "rate",
    "report",
    "sync",
)
_SCP_LIKE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^\s]+$")
_FINISHED = frozenset({ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS})
_ENDED = _FINISHED | {ScanStatus.FAILED, ScanStatus.CANCELLED}


def _check_display_name(value: str) -> str:
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError("display names must not contain control characters")
    return value


def check_repository_url(value: str) -> str:
    """Accept http(s), ssh or scp-like git URLs without embedded credentials.

    The error message never repeats the URL, which may contain a token.
    """
    if _SCP_LIKE.match(value):
        return value
    parts = urlsplit(value)
    if parts.scheme not in ("https", "http", "ssh") or not parts.hostname:
        raise ValueError("repository_url must be an https, http, ssh or git@host:path URL")
    if parts.password is not None:
        raise ValueError("repository_url must not contain a password or token")
    if parts.scheme in ("https", "http") and parts.username is not None:
        raise ValueError("repository_url must not contain a password or token")
    return value


class Project(VersionedModel):
    """A code base that is scanned."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW
    SCHEMA_VERSION: ClassVar[int] = 1

    id: ProjectIdField
    name: str = Field(min_length=1, max_length=200)
    root: str | None = Field(
        default=None,
        description=(
            "Local directory as given by the user; may contain a user name, so reports must "
            "not print it unless asked (E30)."
        ),
    )
    repository_url: str | None = None
    default_privacy_level: PrivacyLevel = PrivacyLevel.L3
    created_at: UtcDatetime

    @field_validator("name")
    @classmethod
    def _single_line(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("name must be a single line")
        return value

    @field_validator("repository_url")
    @classmethod
    def _check_url(cls, value: str | None) -> str | None:
        return None if value is None else check_repository_url(value)


class StageResult(KavachModel):
    """The outcome of one pipeline stage.

    ``error_summary`` is a short static message; callers pass the exception class name and a
    fixed text, never ``str(exc)`` of arbitrary exceptions, which could contain code or file
    content.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    name: str = Field(pattern=STAGE_NAME_PATTERN)
    status: StageStatus
    started_at: UtcDatetime | None = None
    finished_at: UtcDatetime | None = None
    error_code: str | None = Field(default=None, pattern=ERROR_CODE_PATTERN)
    error_summary: str | None = Field(default=None, max_length=500)
    items_in: int | None = Field(default=None, ge=0)
    items_out: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _check_result(self) -> Self:
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.finished_at < self.started_at
        ):
            raise ValueError("finished_at must not be before started_at")
        if (self.status is StageStatus.FAILED) != (self.error_code is not None):
            raise ValueError("error_code is required for failed stages and forbidden otherwise")
        return self


class Scan(VersionedModel):
    """One run of the pipeline over one project."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW
    SCHEMA_VERSION: ClassVar[int] = 1

    id: ScanIdField
    project_id: ProjectIdField
    status: ScanStatus
    started_at: UtcDatetime
    finished_at: UtcDatetime | None = None
    codekavach_version: str = Field(min_length=1, max_length=64)
    config_hash: str = Field(pattern=HEX64_PATTERN)
    git_commit: str | None = Field(default=None, pattern=GIT_COMMIT_PATTERN)
    git_branch: str | None = Field(default=None, max_length=255)
    git_dirty: bool | None = None
    languages: tuple[Language, ...] = ()
    privacy_level: PrivacyLevel
    provider: str | None = Field(default=None, min_length=1, max_length=128)
    model: str | None = Field(default=None, min_length=1, max_length=128)
    stages: tuple[StageResult, ...] = ()
    summary: ScanSummary | None = None

    @field_validator("languages", mode="before")
    @classmethod
    def _sort_languages(cls, value: Any) -> Any:
        if isinstance(value, list | tuple):
            unique = {Language(item) for item in value}
            return tuple(sorted(unique, key=lambda language: language.value))
        return value

    @field_validator("provider", "model")
    @classmethod
    def _display_names(cls, value: str | None) -> str | None:
        return None if value is None else _check_display_name(value)

    @model_validator(mode="after")
    def _check_scan(self) -> Self:
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("finished_at must not be before started_at")
        if self.status in _ENDED and self.finished_at is None:
            raise ValueError("an ended scan needs finished_at")
        if self.status in _FINISHED and self.summary is None:
            raise ValueError("a completed scan needs a summary")
        if self.status not in _ENDED and (self.finished_at is not None or self.summary is not None):
            raise ValueError("a pending or running scan has no finished_at or summary")
        names = [stage.name for stage in self.stages]
        if len(set(names)) != len(names):
            raise ValueError("stage names must be unique within a scan")
        return self

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration, or None while the scan has not ended."""
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @classmethod
    def start(
        cls,
        *,
        project_id: ProjectId,
        codekavach_version: str,
        config_hash: str,
        privacy_level: PrivacyLevel,
        at: datetime,
        **optional: Any,
    ) -> Self:
        """Create a running scan with a new id."""
        return cls.model_validate(
            {
                "id": new_scan_id(),
                "project_id": project_id,
                "status": ScanStatus.RUNNING,
                "started_at": at,
                "codekavach_version": codekavach_version,
                "config_hash": config_hash,
                "privacy_level": privacy_level,
                **optional,
            }
        )

    def with_stage(self, result: StageResult) -> Self:
        """Return a copy with ``result`` replacing the stage of the same name, or appended."""
        stages = list(self.stages)
        for index, stage in enumerate(stages):
            if stage.name == result.name:
                stages[index] = result
                break
        else:
            stages.append(result)
        return self.evolve(stages=tuple(stages))

    def finish(self, status: ScanStatus, summary: ScanSummary | None, at: datetime) -> Self:
        """Return the ended scan; a scan cannot be finished twice."""
        if self.finished_at is not None:
            raise ModelError("the scan has already finished")
        if status in (ScanStatus.PENDING, ScanStatus.RUNNING):
            raise ModelError("finish() needs an end status")
        return self.evolve(status=status, summary=summary, finished_at=at)
