"""The ``[project]`` section.

Owning epic: E03.
"""

from pathlib import Path

from pydantic import Field

from codekavach.config.models.base import SectionModel
from codekavach.core.models import Language


class ProjectSettings(SectionModel):
    """Identity of the scanned project and where its local state lives."""

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Project name for reports; when unset, the root directory name is used.",
    )
    client: str | None = Field(
        default=None,
        max_length=200,
        description="Client organisation shown on the report cover.",
    )
    description: str | None = Field(
        default=None,
        max_length=2000,
        description="One-paragraph description for the scope section of the report.",
    )
    # A string default keeps the JSON Schema default serialisable; validate_default makes it a Path.
    state_dir: Path = Field(
        default=".codekavach",  # type: ignore[assignment]  # converted by validate_default
        description="Directory for the vault, ledger, local database and cache.",
    )
    languages: list[Language] = Field(
        default_factory=list,
        description="Languages to analyse; an empty list means detect them automatically.",
    )
