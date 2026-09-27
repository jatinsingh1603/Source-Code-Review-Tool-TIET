"""The ``[scan]`` section, including the keys consumed by the pipeline (E04).

Owning epic: E03.
"""

from typing import Annotated, Literal

from pydantic import Field, field_validator

from codekavach.config.models.base import INVALID, SectionModel, StrList, bounds, in_range, volatile
from codekavach.core.models import Severity

# ``none`` (never ``never``) disables the threshold in every layer, profile and flag.
FailOn = Severity | Literal["none"]

MAX_GLOB_LENGTH = 256
DEFAULT_EXCLUDE = [
    ".git/**",
    ".codekavach/**",
    "node_modules/**",
    ".venv/**",
    "venv/**",
    "__pycache__/**",
    "dist/**",
    "build/**",
    "target/**",
    "vendor/**",
]


def _check_globs(key: str, values: list[str]) -> list[str]:
    for value in values:
        if not value or len(value) > MAX_GLOB_LENGTH:
            raise ValueError(f"{INVALID} {key} entries must be 1 to {MAX_GLOB_LENGTH} characters")
        if "\\" in value or "\x00" in value:
            raise ValueError(f"{INVALID} {key} entries use / separators and contain no NUL")
    return values


class ScanSettings(SectionModel):
    """What to scan, resource limits and pipeline behaviour."""

    include: StrList = Field(
        default_factory=lambda: ["**/*"],
        description="Glob patterns of files to include, relative to the project root.",
    )
    exclude: StrList = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDE),
        description="Glob patterns of files to exclude, relative to the project root.",
    )
    respect_gitignore: bool = Field(
        default=True, description="Skip files that the repository's .gitignore ignores."
    )
    follow_symlinks: bool = Field(
        default=False, description="Follow symbolic links while discovering files."
    )
    max_file_size_kb: Annotated[int, in_range(1, 102_400, "scan.max_file_size_kb")] = Field(
        default=1024,
        description="Largest file, in kilobytes, that is analysed.",
        json_schema_extra=bounds(1, 102_400),
    )
    max_files: Annotated[int, in_range(1, 5_000_000, "scan.max_files")] = Field(
        default=50_000,
        description="Largest number of files that is analysed.",
        json_schema_extra=bounds(1, 5_000_000),
    )
    max_total_size_mb: Annotated[int, in_range(1, 1_048_576, "scan.max_total_size_mb")] = Field(
        default=2048,
        description="Largest total size, in megabytes, of the analysed files.",
        json_schema_extra=bounds(1, 1_048_576),
    )
    jobs: Annotated[int, in_range(0, 256, "scan.jobs")] = Field(
        default=0,
        description="Number of parallel workers; 0 means the number of CPUs.",
        json_schema_extra=bounds(0, 256) | volatile(),
    )
    timeout_seconds: Annotated[int, in_range(10, 604_800, "scan.timeout_seconds")] = Field(
        default=3600,
        description="Wall-clock limit of a whole scan, in seconds.",
        json_schema_extra=bounds(10, 604_800) | volatile(),
    )
    skip_stages: StrList = Field(
        default_factory=list,
        description="Pipeline stages to skip, by their stage name.",
    )
    fail_on: FailOn = Field(
        default=Severity.HIGH,
        description="Exit non-zero when a finding at or above this severity exists; none disables.",
    )
    cache: bool = Field(
        default=True,
        description="Reuse results of unchanged stages from earlier scans.",
        json_schema_extra=volatile(),
    )
    stage_timeout_seconds: Annotated[int, in_range(10, 86_400, "scan.stage_timeout_seconds")] = (
        Field(
            default=1800,
            description="Default time limit of one pipeline stage, in seconds.",
            json_schema_extra=bounds(10, 86_400) | volatile(),
        )
    )
    stage_timeouts: dict[str, int] = Field(
        default_factory=dict,
        description="Per-stage or per-group time limits in seconds that override the default.",
        json_schema_extra=volatile(),
    )
    cache_max_size_mb: Annotated[int, in_range(64, 1_048_576, "scan.cache_max_size_mb")] = Field(
        default=2048,
        description="Size budget of the stage cache, in megabytes, used when pruning.",
        json_schema_extra=bounds(64, 1_048_576) | volatile(),
    )
    cache_keep_scans: Annotated[int, in_range(1, 1000, "scan.cache_keep_scans")] = Field(
        default=5,
        description="Number of most recent scans whose cache entries survive pruning.",
        json_schema_extra=bounds(1, 1000) | volatile(),
    )

    @field_validator("include")
    @classmethod
    def _check_include(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError(f"{INVALID} scan.include must not be empty")
        return _check_globs("scan.include", value)

    @field_validator("exclude")
    @classmethod
    def _check_exclude(cls, value: list[str]) -> list[str]:
        return _check_globs("scan.exclude", value)

    @field_validator("stage_timeouts")
    @classmethod
    def _check_stage_timeouts(cls, value: dict[str, int]) -> dict[str, int]:
        for seconds in value.values():
            if not 10 <= seconds <= 86_400:
                raise ValueError(f"{INVALID} scan.stage_timeouts values must be 10 to 86400")
        return value
