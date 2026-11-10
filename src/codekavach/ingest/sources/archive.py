"""``ArchiveSource`` and ``safe_extract``: unpack a zip or tar archive under hard limits (E06-03).

Owning epic: E06.

An archive is attacker-controlled input. Two families of bug matter (Zip Slip, a name that joins to
a path outside the root; and decompression bombs, including the non-recursive zip bomb of Fifield,
USENIX WOOT 2019, whose entries overlap so that the declared sizes and the nesting depth look
harmless), so nothing in a header is trusted for a decision that matters.

**Names first.** Every entry name is validated before any path is built: it must be a non-empty
relative POSIX path with no NUL, no backslash, no colon, no ``..`` segment and no more than
``max_path_length`` characters. The destination is then built by this module, one directory at a
time (``mkdir`` of a component that is a link or a file is refused), checked to be inside the
resolved root, and opened with ``O_CREAT | O_EXCL | O_NOFOLLOW``. A second entry of the same name is
refused.

**Links and special members.** No link is ever created. A symbolic or hard link whose target
leaves the root is an error; one that stays inside is skipped and counted, which is why a link
cannot be swapped for a directory between two checks. Device, FIFO and socket members, and
encrypted entries, are errors. Modes and owners are ignored: files are written ``0600`` and
directories ``0700``.

**Limits are enforced on bytes actually produced.** Each entry is streamed through a bounded
reader: ``max_files`` bounds the number of entries, ``max_file_size_bytes`` each entry,
``max_total_bytes`` the running total (checked *before* a chunk is written, so the destination
never holds more than the budget), ``max_depth`` the directory depth of a name. The ratio guard
compares the running decompressed total with the size of the archive file and stops at the first
crossing of ``max_archive_ratio``; overlapping entries cannot hide from it because every entry's
output counts against the same physical size. It applies once a small floor of output
(``RATIO_FLOOR_BYTES``) has been written, so a tiny, highly repetitive archive is not refused.

**Failure.** Any error removes everything written. Messages name a rule or a limit, never an entry
name (it is attacker-chosen and may reach a log).
"""

import os
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, ClassVar, Final

from codekavach.core.log import get_logger
from codekavach.ingest.limits import IngestLimits, LimitExceededError, LimitKind
from codekavach.ingest.sources.base import UnsafeArchiveEntry, UnsupportedSource
from codekavach.ingest.sources.workdir import private_directory, remove_tree

_log = get_logger("codekavach.ingest.sources.archive")

ARCHIVE_SUFFIXES: Final = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
CHUNK_BYTES: Final = 64 * 1024
RATIO_FLOOR_BYTES: Final = 1024 * 1024
LINK_TARGET_MAX_BYTES: Final = 4096
_UNIX_TYPE_MASK: Final = 0o170000
_UNIX_SYMLINK: Final = 0o120000
_UNIX_REGULAR: Final = 0o100000
_UNIX_DIRECTORY: Final = 0o040000
_ZIP_ENCRYPTED_FLAG: Final = 0x1
_O_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
)
_UNREADABLE: Final = "the archive is damaged or uses an unsupported format"


def is_archive_name(name: str) -> bool:
    """Whether ``name`` ends in one of the supported archive extensions (case-insensitive)."""
    return name.lower().endswith(ARCHIVE_SUFFIXES)


def entry_parts(name: str, limits: IngestLimits) -> tuple[str, ...]:
    """The validated path segments of one archive entry name.

    ``()`` is the archive root itself (``./``).

    Raises:
        UnsafeArchiveEntry: the name is empty, absolute, holds a NUL, a backslash, a colon or a
            ``..`` segment, or is longer than ``limits.max_path_length``.
    """
    if not name:
        raise UnsafeArchiveEntry("empty")
    if "\x00" in name:
        raise UnsafeArchiveEntry("nul")
    if "\\" in name:
        raise UnsafeArchiveEntry("backslash")
    if name.startswith("/"):
        raise UnsafeArchiveEntry("absolute")
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        raise UnsafeArchiveEntry("drive_letter")
    if len(name) > limits.max_path_length:
        raise UnsafeArchiveEntry("overlong")
    parts = tuple(part for part in name.split("/") if part not in {"", "."})
    if ".." in parts:
        raise UnsafeArchiveEntry("traversal")
    if any(":" in part for part in parts):
        raise UnsafeArchiveEntry("colon")  # a drive or an alternate data stream on Windows
    return parts


def link_escapes(entry: tuple[str, ...], target: str, *, relative_to_entry: bool) -> bool:
    """Whether a link's ``target`` resolves outside the archive root.

    A symbolic link resolves against the directory of the entry (``relative_to_entry``); a hard
    link names a path from the archive root. An absolute, drive-letter or backslash target is
    treated as an escape without being resolved.
    """
    if not target or "\x00" in target or "\\" in target or target.startswith("/"):
        return True
    if len(target) >= 2 and target[1] == ":" and target[0].isalpha():
        return True
    stack = list(entry[:-1]) if relative_to_entry else []
    for segment in target.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if not stack:
                return True
            stack.pop()
        else:
            stack.append(segment)
    return False


@dataclass
class ExtractionReport:
    """What one extraction wrote and left out; counts only, no names."""

    root: Path
    files: int = 0
    directories: int = 0
    bytes_written: int = 0
    links_skipped: int = 0


@dataclass
class _Run:
    limits: IngestLimits
    archive_bytes: int
    report: ExtractionReport
    entries: int = 0
    seen: set[tuple[str, ...]] = field(default_factory=set)
    known_dirs: set[tuple[str, ...]] = field(default_factory=set)

    def count_entry(self) -> None:
        self.entries += 1
        if self.entries > self.limits.max_files:
            raise LimitExceededError(LimitKind.ARCHIVE_ENTRIES, self.limits.max_files)

    def charge(self, size: int) -> None:
        """Account for ``size`` bytes about to be written; raise before they are."""
        total = self.report.bytes_written + size
        if total > self.limits.max_total_bytes:
            raise LimitExceededError(LimitKind.TOTAL_BYTES, self.limits.max_total_bytes)
        if total > RATIO_FLOOR_BYTES and total > self.limits.max_archive_ratio * max(
            self.archive_bytes, 1
        ):
            raise LimitExceededError(LimitKind.ARCHIVE_RATIO, self.limits.max_archive_ratio)
        self.report.bytes_written = total


def _check_depth(parts: tuple[str, ...], *, is_dir: bool, limits: IngestLimits) -> None:
    directories = len(parts) if is_dir else len(parts) - 1
    if directories > limits.max_depth:
        raise LimitExceededError(LimitKind.DEPTH, limits.max_depth)


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _make_directories(run: "_Run", root: Path, parts: tuple[str, ...]) -> Path:
    """Create ``root/parts`` one component at a time, refusing a link or a file in the way.

    A directory that was checked once in this extraction is not checked again: no link is ever
    created, so nothing can turn it into one afterwards.
    """
    current = root
    for depth, part in enumerate(parts, start=1):
        current = current / part
        prefix = parts[:depth]
        if prefix in run.known_dirs:
            continue
        try:
            if current.is_symlink():
                raise UnsafeArchiveEntry("link_in_path")
            if current.exists():
                if not current.is_dir():
                    raise UnsafeArchiveEntry("file_in_path")
            else:
                current.mkdir(mode=0o700)
        except OSError:
            raise UnsafeArchiveEntry("unwritable") from None
        if not _within(current, root):
            raise UnsafeArchiveEntry("traversal")
        run.known_dirs.add(prefix)
    return current


def _write_entry(
    run: _Run, root: Path, parts: tuple[str, ...], declared: int, source: IO[bytes]
) -> None:
    """Stream ``source`` into ``root/parts`` under every budget; a declared size is not trusted."""
    limits = run.limits
    if declared > limits.max_file_size_bytes:
        raise LimitExceededError(LimitKind.FILE_SIZE, limits.max_file_size_bytes)
    if parts in run.seen:
        raise UnsafeArchiveEntry("duplicate")
    destination = _make_directories(run, root, parts[:-1]) / parts[-1]
    try:
        descriptor = os.open(destination, _O_FLAGS, 0o600)
    except FileExistsError:
        raise UnsafeArchiveEntry("duplicate") from None
    except OSError:
        raise UnsafeArchiveEntry("unwritable") from None
    run.seen.add(parts)
    written = 0
    with os.fdopen(descriptor, "wb") as handle:
        while True:
            chunk = source.read(CHUNK_BYTES)
            if not chunk:
                break
            written += len(chunk)
            if written > limits.max_file_size_bytes:
                raise LimitExceededError(LimitKind.FILE_SIZE, limits.max_file_size_bytes)
            run.charge(len(chunk))
            handle.write(chunk)
    run.report.files += 1


def _zip_kind(info: zipfile.ZipInfo) -> str:
    mode = (info.external_attr >> 16) & _UNIX_TYPE_MASK
    if info.is_dir() or mode == _UNIX_DIRECTORY:
        return "directory"
    if mode == _UNIX_SYMLINK:
        return "symlink"
    if mode in {0, _UNIX_REGULAR}:
        return "file"
    return "special"


def _extract_zip(archive: Path, root: Path, run: _Run) -> None:
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            run.count_entry()
            parts = entry_parts(info.filename, run.limits)
            kind = _zip_kind(info)
            if kind == "special":
                raise UnsafeArchiveEntry("special_member")
            if info.flag_bits & _ZIP_ENCRYPTED_FLAG:
                raise UnsafeArchiveEntry("encrypted")
            if not parts:
                continue
            _check_depth(parts, is_dir=kind == "directory", limits=run.limits)
            if kind == "directory":
                _make_directories(run, root, parts)
                run.report.directories += 1
            elif kind == "symlink":
                with bundle.open(info) as stream:
                    target = stream.read(LINK_TARGET_MAX_BYTES + 1)
                if len(target) > LINK_TARGET_MAX_BYTES:
                    raise UnsafeArchiveEntry("link_escape")
                if link_escapes(parts, target.decode("utf-8", "replace"), relative_to_entry=True):
                    raise UnsafeArchiveEntry("link_escape")
                run.report.links_skipped += 1
            else:
                with bundle.open(info) as stream:
                    _write_entry(run, root, parts, info.file_size, stream)


def _tar_members(bundle: tarfile.TarFile) -> Iterator[tarfile.TarInfo]:
    while (member := bundle.next()) is not None:
        yield member


def _extract_tar(archive: Path, root: Path, run: _Run) -> None:
    with tarfile.open(archive, mode="r|*") as bundle:
        for member in _tar_members(bundle):
            run.count_entry()
            parts = entry_parts(member.name, run.limits)
            if member.isdev() or member.isfifo():
                raise UnsafeArchiveEntry("special_member")
            if member.issym() or member.islnk():
                escapes = link_escapes(parts, member.linkname, relative_to_entry=member.issym())
                if escapes:
                    raise UnsafeArchiveEntry("link_escape")
                run.report.links_skipped += 1
                continue
            if not parts:
                continue
            if member.isdir():
                _check_depth(parts, is_dir=True, limits=run.limits)
                _make_directories(run, root, parts)
                run.report.directories += 1
                continue
            if not member.isreg():
                raise UnsafeArchiveEntry("special_member")
            _check_depth(parts, is_dir=False, limits=run.limits)
            stream = bundle.extractfile(member)
            if stream is None:
                raise UnsafeArchiveEntry("special_member")
            with stream:
                _write_entry(run, root, parts, member.size, stream)


def safe_extract(archive: Path, into: Path, limits: IngestLimits) -> Path:
    """Extract ``archive`` into ``into`` and return ``into``.

    ``into`` is created with mode ``0700`` and is removed again, with everything in it, on any
    failure.

    Raises:
        LimitExceededError: a count, size, depth or ratio budget was crossed.
        UnsafeArchiveEntry: an entry name, link or member type is not acceptable.
        UnsupportedSource: the file is not a readable archive of a supported format.
    """
    report = ExtractionReport(root=into)
    try:
        size = archive.stat().st_size
        private_directory(into)
        root = into.resolve()
        run = _Run(limits=limits, archive_bytes=size, report=report)
        if archive.name.lower().endswith(".zip"):
            _extract_zip(archive, root, run)
        else:
            _extract_tar(archive, root, run)
    except (zipfile.BadZipFile, tarfile.TarError, zlib.error, EOFError, NotImplementedError):
        remove_tree(into)
        raise UnsupportedSource(_UNREADABLE) from None
    except (OSError, RuntimeError):
        remove_tree(into)
        raise UnsupportedSource(_UNREADABLE) from None
    except BaseException:
        remove_tree(into)
        raise
    _log.info(
        "archive_extracted",
        files=report.files,
        directories=report.directories,
        links_skipped=report.links_skipped,
        bytes=report.bytes_written,
    )
    return into


class ArchiveSource:
    """Serves a zip or tar archive on the local disk by extracting it into the scratch directory."""

    owns_root: ClassVar[bool] = True

    def materialise(self, target: str, *, limits: IngestLimits, into: Path) -> Path:
        """Extract ``target`` into ``into`` and return it."""
        path = Path(target)
        try:
            usable = is_archive_name(path.name) and path.is_file()
        except OSError:
            usable = False
        if not usable:
            raise UnsupportedSource("the target is not a supported archive file")
        return safe_extract(path, into, limits)
