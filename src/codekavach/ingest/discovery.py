"""The repository discovery walk: ``discover`` and ``build_inventory`` (E06-01).

Owning epic: E06.

Walks with ``os.scandir`` and sorts each directory's entries before descending, so two runs over
the same tree give byte-identical output regardless of file-system enumeration order (the stage
cache key, E04-21, is derived from it). A symlink is never traversed when
``ingest.follow_symlinks`` is false (the default, and the only value untrusted project
configuration may set, E03-25): skipping every symlink outright, rather than detecting a loop
while following one, is also why a symlink loop cannot hang this walk.
"""

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from codekavach.config.models.root import Settings
from codekavach.core.models import Language, split_lines
from codekavach.ingest.classify import is_binary, is_generated, is_minified, is_vendored
from codekavach.ingest.encoding import UndecodableFileError, decode
from codekavach.ingest.filters import IgnoreSet
from codekavach.ingest.limits import (
    MAX_PATH_LENGTH,
    IngestLimits,
    LimitExceededError,
    LimitKind,
    SkipReason,
)
from codekavach.ingest.models import FileInventory, SourceFile

# Read only this many bytes to decide binary/generated status before deciding whether to read
# (and hash) the whole file; keeps classification cheap even for a file at the size limit.
HEAD_SNIFF_BYTES = 8192


@dataclass
class DiscoveryReport:
    """Per-``SkipReason`` counts from one discovery run, for the report's coverage appendix."""

    skipped: dict[SkipReason, int] = field(default_factory=dict)

    def record(self, reason: SkipReason) -> None:
        """Count one more skipped candidate against ``reason``."""
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def _is_symlink_like(entry: os.DirEntry[str]) -> bool:
    return entry.is_symlink()


def _within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _walk(
    root: Path, limits: IngestLimits, ignores: IgnoreSet, report: DiscoveryReport
) -> list[tuple[Path, str]]:
    """Every readable, non-excluded file path, as ``(absolute_path, posix_rel_path)`` pairs."""
    accepted: list[tuple[Path, str]] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            rel_path = Path(entry.path).relative_to(root).as_posix()
            if len(entry.path) > MAX_PATH_LENGTH:
                report.record(SkipReason.UNREADABLE)
                continue
            if _is_symlink_like(entry):
                if not limits.follow_symlinks:
                    report.record(SkipReason.SYMLINK)
                    continue
                if not _within_root(Path(entry.path), root):
                    report.record(SkipReason.SYMLINK)
                    continue
            is_dir = entry.is_dir(follow_symlinks=limits.follow_symlinks)
            if ignores.matches(rel_path, is_dir=is_dir):
                report.record(SkipReason.IGNORED)
                continue
            if is_dir:
                if depth + 1 > limits.max_depth:
                    continue
                stack.append((Path(entry.path), depth + 1))
                continue
            accepted.append((Path(entry.path), rel_path))
    accepted.sort(key=lambda pair: pair[1].encode("utf-8"))
    return accepted


def _read_source_file(
    path: Path, rel_path: str, limits: IngestLimits, report: DiscoveryReport
) -> SourceFile | None:
    try:
        size = path.stat().st_size
    except OSError:
        report.record(SkipReason.UNREADABLE)
        return None
    if size > limits.max_file_size_bytes:
        report.record(SkipReason.TOO_LARGE)
        return None
    try:
        data = path.read_bytes()
    except OSError:
        report.record(SkipReason.UNREADABLE)
        return None
    if is_binary(data[:HEAD_SNIFF_BYTES]):
        report.record(SkipReason.BINARY)
        return None
    try:
        text, encoding = decode(data, limits.legacy_encoding)
    except UndecodableFileError:
        report.record(SkipReason.UNDECODABLE)
        return None
    line_count = len(split_lines(text))
    sha256 = hashlib.sha256(data).hexdigest()
    return SourceFile(
        path=rel_path,
        sha256=sha256,
        size_bytes=size,
        language=Language.UNKNOWN,
        line_count=line_count,
        encoding=encoding,
        is_generated=is_generated(rel_path, "\n".join(text.split("\n")[:5])),
        is_minified=is_minified(rel_path, text, line_count),
        is_vendored=is_vendored(rel_path),
    )


def discover(root: Path, settings: Settings) -> list[SourceFile]:
    """Discover every readable, non-excluded text file under ``root``, sorted by path.

    Raises:
        LimitExceededError: ``ingest.max_files`` or ``ingest.max_total_bytes`` was exceeded.
    """
    limits = IngestLimits.from_settings(settings.ingest)
    ignores = IgnoreSet.from_root(root, settings.ingest)
    report = DiscoveryReport()
    candidates = _walk(root, limits, ignores, report)

    files: list[SourceFile] = []
    total_bytes = 0
    for path, rel_path in candidates:
        source_file = _read_source_file(path, rel_path, limits, report)
        if source_file is None:
            continue
        if len(files) + 1 > limits.max_files:
            raise LimitExceededError(LimitKind.FILE_COUNT, limits.max_files)
        total_bytes += source_file.size_bytes
        if total_bytes > limits.max_total_bytes:
            raise LimitExceededError(LimitKind.TOTAL_BYTES, limits.max_total_bytes)
        files.append(source_file)
    return files


def build_inventory(files: Sequence[SourceFile]) -> FileInventory:
    """Aggregate ``files`` into one ``FileInventory``.

    Languages are sorted by descending line count, ties broken by enum value (ascending), so the
    result is deterministic regardless of the order ``files`` arrives in.
    """
    totals: dict[Language, int] = {}
    total_lines = 0
    total_bytes = 0
    for source_file in files:
        totals[source_file.language] = totals.get(source_file.language, 0) + source_file.line_count
        total_lines += source_file.line_count
        total_bytes += source_file.size_bytes
    languages = tuple(sorted(totals.items(), key=lambda pair: (-pair[1], pair[0].value)))
    return FileInventory(
        total_files=len(files),
        total_lines=total_lines,
        total_bytes=total_bytes,
        languages=languages,
    )
