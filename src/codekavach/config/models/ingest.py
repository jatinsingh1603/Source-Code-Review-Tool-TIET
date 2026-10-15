"""The ``[ingest]`` section: resource limits and exclusions for repository discovery (E06-01).

Owning epic: E03 (section conventions); consumed by E06.

``follow_symlinks`` is restricted (E03-25): untrusted project configuration may not turn it on,
because a symlink followed out of the project root is how a crafted repository reads files it
should not (CWE-59). ``excludes`` merges by union across layers (E03-13): a project file may add
an exclusion, but removing one of the defaults below has no effect, so a crafted project cannot
re-include ``.git`` or ``node_modules`` by naming it as an "include" later.
"""

from typing import Annotated

from pydantic import Field, field_validator

from codekavach.config.models.base import (
    INVALID,
    SectionModel,
    StrList,
    bounds,
    in_range,
    restricted,
    union_merge,
)

MAX_GLOB_LENGTH = 256
DEFAULT_EXCLUDES = ["node_modules", "vendor", "build", "dist", ".git", "**/*.min.js"]


def _check_globs(key: str, values: list[str]) -> list[str]:
    for value in values:
        if not value or len(value) > MAX_GLOB_LENGTH:
            raise ValueError(f"{INVALID} {key} entries must be 1 to {MAX_GLOB_LENGTH} characters")
        if "\\" in value or "\x00" in value:
            raise ValueError(f"{INVALID} {key} entries use / separators and contain no NUL")
    return values


class IngestSettings(SectionModel):
    """Resource guards and exclusions applied while discovering repository files."""

    max_file_size_bytes: Annotated[
        int, in_range(1, 1_000_000_000, "ingest.max_file_size_bytes")
    ] = Field(
        default=5_000_000,
        description="Largest single file, in bytes, that is read.",
        json_schema_extra=bounds(1, 1_000_000_000),
    )
    max_files: Annotated[int, in_range(1, 10_000_000, "ingest.max_files")] = Field(
        default=50_000,
        description="Largest number of files that discovery returns.",
        json_schema_extra=bounds(1, 10_000_000),
    )
    max_total_bytes: Annotated[int, in_range(1, 1_000_000_000_000, "ingest.max_total_bytes")] = (
        Field(
            default=2_000_000_000,
            description="Largest total size, in bytes, of every file discovery accepts.",
            json_schema_extra=bounds(1, 1_000_000_000_000),
        )
    )
    max_archive_ratio: Annotated[int, in_range(1, 100_000, "ingest.max_archive_ratio")] = Field(
        default=100,
        description="Largest decompressed-to-compressed size ratio an archive source may have.",
        json_schema_extra=bounds(1, 100_000),
    )
    max_depth: Annotated[int, in_range(1, 1000, "ingest.max_depth")] = Field(
        default=25,
        description="Deepest directory, in path segments below the root, that is walked.",
        json_schema_extra=bounds(1, 1000),
    )
    follow_symlinks: bool = Field(
        default=False,
        description="Follow symbolic links while discovering files.",
        json_schema_extra=restricted(),
    )
    respect_gitignore: bool = Field(
        default=True, description="Skip files that a .gitignore in the tree ignores."
    )
    excludes: StrList = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDES),
        description="Glob patterns excluded from discovery in addition to .gitignore.",
        json_schema_extra=union_merge(),
    )
    legacy_encoding: str = Field(
        default="cp1252",
        description="Fallback text encoding tried after UTF-8 and UTF-16 fail to decode a file.",
    )

    @field_validator("legacy_encoding")
    @classmethod
    def _check_legacy_encoding(cls, value: str) -> str:
        try:
            "".encode(value)
        except LookupError:
            raise ValueError(f"{INVALID} ingest.legacy_encoding names an unknown codec") from None
        return value

    @field_validator("excludes")
    @classmethod
    def _check_excludes(cls, value: list[str]) -> list[str]:
        return _check_globs("ingest.excludes", value)
