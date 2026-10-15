"""Resource limits and why a file was skipped during discovery (E06-01).

Owning epic: E06.

``LimitExceededError`` carries the budget and the kind of limit, never a path or its contents: a
limit breach is reported to an operator and may reach a log, so its message must be safe on its
own (CWE-400, CWE-409 precaution, not a fix for a published vulnerability).
"""

from enum import StrEnum

from codekavach.config.models.ingest import IngestSettings


class LimitKind(StrEnum):
    """Which budget a discovery walk hit."""

    FILE_SIZE = "file_size"
    FILE_COUNT = "file_count"
    TOTAL_BYTES = "total_bytes"
    DEPTH = "depth"
    PATH_LENGTH = "path_length"
    ARCHIVE_RATIO = "archive_ratio"
    ARCHIVE_ENTRIES = "archive_entries"


class SkipReason(StrEnum):
    """Why one candidate path was left out of the inventory, never a hard failure."""

    BINARY = "binary"
    TOO_LARGE = "too_large"
    EXCLUDED = "excluded"
    IGNORED = "ignored"
    SYMLINK = "symlink"
    UNREADABLE = "unreadable"
    UNDECODABLE = "undecodable"
    GENERATED = "generated"
    MINIFIED = "minified"
    VENDORED = "vendored"


MAX_PATH_LENGTH = 4096


class LimitExceededError(Exception):
    """A hard budget was exceeded; the scan for this candidate aborts, fail closed.

    ``str(error)`` names the kind and the numeric budget only, never a path.
    """

    def __init__(self, kind: LimitKind, budget: int) -> None:
        self.kind = kind
        self.budget = budget
        super().__init__(f"ingest limit {kind.value!r} exceeded (budget {budget})")


class IngestLimits:
    """A frozen, read-only view of the ``[ingest]`` resource guards."""

    __slots__ = (
        "excludes",
        "follow_symlinks",
        "legacy_encoding",
        "max_archive_ratio",
        "max_depth",
        "max_file_size_bytes",
        "max_files",
        "max_path_length",
        "max_total_bytes",
        "respect_gitignore",
    )

    def __init__(
        self,
        *,
        max_file_size_bytes: int,
        max_files: int,
        max_total_bytes: int,
        max_archive_ratio: int,
        max_depth: int,
        follow_symlinks: bool,
        respect_gitignore: bool,
        excludes: tuple[str, ...],
        legacy_encoding: str,
        max_path_length: int = MAX_PATH_LENGTH,
    ) -> None:
        self.max_file_size_bytes = max_file_size_bytes
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_archive_ratio = max_archive_ratio
        self.max_depth = max_depth
        self.follow_symlinks = follow_symlinks
        self.respect_gitignore = respect_gitignore
        self.excludes = excludes
        self.legacy_encoding = legacy_encoding
        self.max_path_length = max_path_length

    @classmethod
    def from_settings(cls, settings: IngestSettings) -> "IngestLimits":
        """Build the frozen view from one ``IngestSettings`` instance."""
        return cls(
            max_file_size_bytes=settings.max_file_size_bytes,
            max_files=settings.max_files,
            max_total_bytes=settings.max_total_bytes,
            max_archive_ratio=settings.max_archive_ratio,
            max_depth=settings.max_depth,
            follow_symlinks=settings.follow_symlinks,
            respect_gitignore=settings.respect_gitignore,
            excludes=tuple(settings.excludes),
            legacy_encoding=settings.legacy_encoding,
        )
