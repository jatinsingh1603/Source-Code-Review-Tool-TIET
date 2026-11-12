"""The ``[aggregate]`` and ``[secrets]`` sections: baselines, suppressions, history (#236, #240).

Owning epic: E03 (section conventions); consumed by ``codekavach.analysis.aggregate`` and
``codekavach.analysis.secrets`` and by the ``baseline``, ``suppress``, ``secrets`` and ``diff``
commands. Both file settings are paths relative to the project root.
"""

from typing import Annotated

from pydantic import Field, field_validator

from codekavach.config.models.base import INVALID, SectionModel, bounds, in_range


def _relative(key: str, value: str) -> str:
    if not value or len(value) > 256 or "\x00" in value:
        raise ValueError(f"{INVALID} {key} must be 1 to 256 characters")
    normal = value.replace("\\", "/")
    if (
        normal.startswith("/")
        or (len(normal) > 1 and normal[1] == ":")
        or ".." in normal.split("/")
    ):
        raise ValueError(f"{INVALID} {key} must be a path inside the project root")
    return normal


class AggregateSettings(SectionModel):
    """Where the accepted-findings baseline and the suppression rules live."""

    baseline_file: str = Field(
        default=".codekavach/baseline.json",
        description=(
            "Baseline of accepted findings, relative to the project root; findings in it are "
            "known and are not reviewed again."
        ),
    )
    suppressions_file: str = Field(
        default=".codekavach/suppressions.yaml",
        description=(
            "Suppression rules, relative to the project root; every rule needs a justification."
        ),
    )

    @field_validator("baseline_file")
    @classmethod
    def _check_baseline(cls, value: str) -> str:
        return _relative("aggregate.baseline_file", value)

    @field_validator("suppressions_file")
    @classmethod
    def _check_suppressions(cls, value: str) -> str:
        return _relative("aggregate.suppressions_file", value)


class SecretsSettings(SectionModel):
    """Options of the secret scan beyond the working tree."""

    history: bool = Field(
        default=False,
        description="Also scan the added lines of past commits for credentials that were removed.",
    )
    history_max_commits: Annotated[int, in_range(1, 5000, "secrets.history_max_commits")] = Field(
        default=200,
        description="Most recent commits the history scan reads.",
        json_schema_extra=bounds(1, 5000),
    )
