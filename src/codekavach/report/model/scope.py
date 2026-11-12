"""Engagement scope, coverage and limitations.

Owning epic: E30 (E30-01).
"""

from typing import ClassVar

from pydantic import Field

from codekavach.core.models.base import DataClassification, KavachModel


class Target(KavachModel):
    """One code base in scope."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    repository: str
    commit: str | None = None
    branch: str | None = None
    languages: tuple[str, ...] = ()
    paths_included: tuple[str, ...] = ()
    paths_excluded: tuple[str, ...] = ()


class EngagementScope(KavachModel):
    """What was reviewed, for whom, when and why."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    client_name: str
    engagement_id: str
    engagement_type: str = "Secure source code review (white-box, automated with model assistance)"
    period_start: str
    period_end: str
    targets: tuple[Target, ...] = ()
    assumptions: tuple[str, ...] = ()
    objectives: tuple[str, ...] = ()


class Coverage(KavachModel):
    """How much of the code base the analysis reached."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    files_discovered: int = Field(default=0, ge=0)
    files_analysed: int = Field(default=0, ge=0)
    lines_analysed: int = Field(default=0, ge=0)
    by_language: tuple[tuple[str, int], ...] = ()
    candidates_total: int = Field(default=0, ge=0)
    candidates_reviewed_by_llm: int = Field(default=0, ge=0)
    not_reviewed: tuple[tuple[str, int], ...] = ()
    files_reviewed: tuple[str, ...] = ()


class Limitation(KavachModel):
    """One stated limitation of the review."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    id: str
    kind: str
    statement: str
