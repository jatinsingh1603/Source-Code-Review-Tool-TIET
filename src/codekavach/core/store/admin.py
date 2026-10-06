"""Housekeeping of the cache: statistics, pruning to a size budget, cleanup (E04-23).

Owning epic: E04.

The content-addressed store never overwrites, so it only grows: every scan adds blobs, stage
records and memo entries below ``<state>/cache``. ``CacheAdmin`` keeps that bounded and removes
what a crash or a hard exit leaves behind. It touches only ``cache/`` and ``scans/``; the vault,
the ledger and the database belong to other modules and are not looked at.

``prune`` works in six steps:

1. temporary files (``.*.tmp``) older than one hour are deleted;
2. the blobs referenced by the bindings of the ``keep_scans`` newest scans are protected (scan ids
   are ULIDs, so their order is time order);
3. older scan directories are deleted (the database rows are not touched);
4. when blobs and memo entries together exceed ``max_bytes``, unprotected blobs and all memo
   entries are deleted oldest first until the total is at or below 90 per cent of the budget (the
   hysteresis keeps a scan from pruning every time it ends);
5. stage cache records that point at a missing blob are deleted, because they would be hits that
   cannot be served;
6. empty shard directories are removed.

Recency is the modification time, which a cache hit refreshes (``touch``); the access time is not
used because ``noatime`` mounts make it unreliable.

Safety: paths come from ``os.scandir`` below ``cache/`` and ``scans/`` only, symbolic links are
neither followed nor deleted, and a file that has already gone (another process may prune at the
same time) is ignored. A scan running in another process keeps its bindings because its scan
directory is among the newest; if its blobs were removed anyway, its next read raises
``ArtefactMissingError`` and the stage fails under the normal policy. There is no cross-process
lock.

Deleting is ``os.unlink``. It is not secure erasure: pruned client-derived data may be
recoverable from the disk until the blocks are reused.
"""

import contextlib
import json
import os
import re
import shutil
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import JsonValue

from codekavach.core.log import get_logger
from codekavach.core.store.layout import StateLayout

TMP_MAX_AGE_SECONDS: Final = 3600.0
HYSTERESIS: Final = 0.9
_SCAN_ID: Final = re.compile(r"^scan_[0-9A-HJKMNP-TV-Z]{26}$")
_log = get_logger("codekavach.store.admin")


@dataclass(frozen=True, slots=True)
class CacheStats:
    """What is below ``cache/`` and ``scans/``; no file content is read to produce it."""

    blob_count: int = 0
    blob_bytes: int = 0
    stage_records: int = 0
    item_entries: int = 0
    item_bytes: int = 0
    scan_count: int = 0
    tmp_files: int = 0


@dataclass(frozen=True, slots=True)
class PruneReport:
    """What one ``prune`` or ``clear`` removed; ``remaining_bytes`` is blobs plus memo entries."""

    removed_blobs: int = 0
    removed_items: int = 0
    removed_records: int = 0
    removed_scans: int = 0
    removed_tmp: int = 0
    freed_bytes: int = 0
    remaining_bytes: int = 0


@dataclass(frozen=True, slots=True)
class _File:
    path: Path
    size: int
    mtime: float


def _is_tmp(name: str) -> bool:
    return name.startswith(".") and name.endswith(".tmp")


def _files(root: Path) -> Iterator[_File]:
    """Every regular file below ``root``; symbolic links are skipped and never followed."""
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError:  # gone, not a directory, or not readable: nothing to count
            continue
        for entry in children:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    info = entry.stat(follow_symlinks=False)
                    yield _File(Path(entry.path), info.st_size, info.st_mtime)
            except OSError:
                continue


def _unlink(file: _File) -> bool:
    """Delete ``file``; True when this call removed it, False when it was already gone or stays."""
    try:
        file.path.unlink()
    except FileNotFoundError:
        return False
    except OSError as error:
        _log.warning("cache_remove_failed", error_type=type(error).__name__)
        return False
    return True


def _delete_all(files: Iterable[_File]) -> tuple[int, int]:
    """Delete every file; the number removed and the bytes freed."""
    removed = freed = 0
    for file in files:
        if _unlink(file):
            removed += 1
            freed += file.size
    return removed, freed


def _directory_size(directory: Path) -> int:
    return sum(file.size for file in _files(directory))


def _delete_directories(directories: Iterable[Path]) -> tuple[int, int]:
    """Remove scan directories without following links; the number removed and bytes freed."""
    removed = freed = 0
    for directory in directories:
        size = _directory_size(directory)
        shutil.rmtree(directory, ignore_errors=True)
        if not directory.exists():
            removed += 1
            freed += size
    return removed, freed


def _directories(root: Path) -> Iterator[Path]:
    """Every directory below ``root`` (not ``root``), links not followed."""
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                children = [
                    Path(entry.path)
                    for entry in entries
                    if entry.is_dir(follow_symlinks=False) and not entry.is_symlink()
                ]
        except OSError:
            continue
        stack.extend(children)
        yield from children


def _remove_empty_directories(root: Path) -> None:
    """Delete empty directories below ``root`` (not ``root`` itself), deepest first."""
    for directory in sorted(_directories(root), key=lambda path: -len(path.parts)):
        with contextlib.suppress(OSError):
            directory.rmdir()  # fails when it is not empty, which is what we want


def touch(path: Path) -> None:
    """Refresh the modification time of ``path``, which is the recency signal; best effort."""
    with contextlib.suppress(OSError):
        os.utime(path)


class CacheAdmin:
    """Statistics, pruning and clearing of the cache of one state directory."""

    def __init__(self, layout: StateLayout) -> None:
        self._layout = layout

    @property
    def _cache(self) -> Path:
        return self._layout.root / "cache"

    @property
    def _scans(self) -> Path:
        return self._layout.scans_dir

    def _blob_files(self) -> list[_File]:
        return [file for file in _files(self._layout.blobs_dir) if not _is_tmp(file.path.name)]

    def _item_files(self) -> list[_File]:
        root = self._cache / "items"
        return [file for file in _files(root) if not _is_tmp(file.path.name)]

    def _record_files(self) -> list[_File]:
        root = self._cache / "stages"
        return [file for file in _files(root) if not _is_tmp(file.path.name)]

    def _tmp_files(self) -> list[_File]:
        return [
            file
            for top in (self._cache, self._scans)
            for file in _files(top)
            if _is_tmp(file.path.name)
        ]

    def _scan_directories(self) -> list[Path]:
        """The scan record directories, oldest first."""
        try:
            with os.scandir(self._scans) as entries:
                return sorted(
                    (
                        Path(entry.path)
                        for entry in entries
                        if _SCAN_ID.match(entry.name)
                        and entry.is_dir(follow_symlinks=False)
                        and not entry.is_symlink()
                    ),
                    key=lambda path: path.name,
                )
        except OSError:
            return []

    # --- statistics ----------------------------------------------------------------------------

    def stats(self) -> CacheStats:
        """The counts and byte totals of the cache; reads no file content."""
        blobs, items = self._blob_files(), self._item_files()
        return CacheStats(
            blob_count=len(blobs),
            blob_bytes=sum(file.size for file in blobs),
            stage_records=len(self._record_files()),
            item_entries=len(items),
            item_bytes=sum(file.size for file in items),
            scan_count=len(self._scan_directories()),
            tmp_files=len(self._tmp_files()),
        )

    # --- pruning -------------------------------------------------------------------------------

    def prune(self, max_bytes: int, keep_scans: int, *, now: float | None = None) -> PruneReport:
        """Bring the cache below ``max_bytes`` while keeping the ``keep_scans`` newest scans whole.

        ``now`` is the clock for the age of temporary files; it is injected by tests.

        Raises:
            ValueError: ``max_bytes`` is negative or ``keep_scans`` is less than 1.
        """
        if max_bytes < 0:
            raise ValueError("max_bytes must not be negative")
        if keep_scans < 1:
            raise ValueError("keep_scans must be at least 1")
        clock = time.time() if now is None else now
        stale = [file for file in self._tmp_files() if clock - file.mtime > TMP_MAX_AGE_SECONDS]
        removed_tmp, freed = _delete_all(stale)
        scans = self._scan_directories()
        keep, drop = scans[-keep_scans:], scans[:-keep_scans]
        protected = self._protected_digests(keep)
        removed_scans, freed_scans = _delete_directories(drop)
        removed_blobs, removed_items, freed_content = self._evict(max_bytes, protected)
        removed_records, freed_records = self._drop_dangling_records()
        for top in (self._layout.blobs_dir, self._cache / "stages", self._cache / "items"):
            _remove_empty_directories(top)
        return PruneReport(
            removed_blobs=removed_blobs,
            removed_items=removed_items,
            removed_records=removed_records,
            removed_scans=removed_scans,
            removed_tmp=removed_tmp,
            freed_bytes=freed + freed_scans + freed_content + freed_records,
            remaining_bytes=self._content_bytes(),
        )

    def _content_bytes(self) -> int:
        return sum(file.size for file in self._blob_files() + self._item_files())

    def _protected_digests(self, scan_directories: list[Path]) -> set[str]:
        """Every blob digest that a binding of the given scans refers to."""
        digests: set[str] = set()
        for directory in scan_directories:
            for file in _files(directory / "index"):
                if file.path.suffix != ".json":
                    continue
                try:
                    binding = json.loads(file.path.read_bytes())
                except (OSError, ValueError):
                    _log.warning("cache_binding_unreadable", scan=directory.name)
                    continue
                digests.update(_binding_digests(binding))
        return digests

    def _evict(self, max_bytes: int, protected: set[str]) -> tuple[int, int, int]:
        """Delete the oldest unprotected blobs and memo entries; (blobs, items, freed bytes)."""
        blobs, items = self._blob_files(), self._item_files()
        total = sum(file.size for file in blobs) + sum(file.size for file in items)
        if total <= max_bytes:
            return 0, 0, 0
        target = int(max_bytes * HYSTERESIS)
        candidates = [(file, "blob") for file in blobs if file.path.name not in protected]
        candidates += [(file, "item") for file in items]
        candidates.sort(key=lambda pair: (pair[0].mtime, str(pair[0].path)))
        removed_blobs = removed_items = freed = 0
        for file, kind in candidates:
            if total <= target:
                break
            if _unlink(file):
                freed += file.size
                removed_blobs += kind == "blob"
                removed_items += kind == "item"
            elif file.path.exists():
                continue  # it stays, so the total does not change
            total -= file.size  # removed here, or already gone
        return removed_blobs, removed_items, freed

    def _drop_dangling_records(self) -> tuple[int, int]:
        """Delete stage records that are unreadable or point at a blob that no longer exists."""
        return _delete_all(
            file for file in self._record_files() if not self._record_is_servable(file.path)
        )

    def _record_is_servable(self, path: Path) -> bool:
        try:
            record = json.loads(path.read_bytes())
            digests = _record_digests(record)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return False
        return all(self._blob_exists(digest) for digest in digests)

    def _blob_exists(self, digest: str) -> bool:
        try:
            return self._layout.blob_path(digest).is_file()
        except Exception:  # noqa: BLE001 - a malformed digest in a record means it is unusable
            return False

    # --- clearing ------------------------------------------------------------------------------

    def clear(self, *, include_scans: bool = False) -> PruneReport:
        """Remove everything below ``cache/``, and with ``include_scans`` below ``scans/`` too.

        Nothing else in the state directory is touched, and symbolic links are left alone.
        """
        removed_blobs, freed_blobs = _delete_all(self._blob_files())
        removed_items, freed_items = _delete_all(self._item_files())
        removed_records, freed_records = _delete_all(self._record_files())
        removed_tmp, freed_tmp = _delete_all(self._tmp_files())
        removed_scans = freed_scans = 0
        if include_scans:
            removed_scans, freed_scans = _delete_directories(self._scan_directories())
        for top in (self._cache, self._scans) if include_scans else (self._cache,):
            _remove_empty_directories(top)
        return PruneReport(
            removed_blobs=removed_blobs,
            removed_items=removed_items,
            removed_records=removed_records,
            removed_scans=removed_scans,
            removed_tmp=removed_tmp,
            freed_bytes=freed_blobs + freed_items + freed_records + freed_tmp + freed_scans,
            remaining_bytes=self._content_bytes(),
        )


def _binding_digests(binding: object) -> set[str]:
    """The blob digests that one binding file refers to; an unknown shape refers to none."""
    digests: set[str] = set()
    if not isinstance(binding, dict):
        return digests
    digest = binding.get("digest")
    if isinstance(digest, str):
        digests.add(digest)
    parts = binding.get("parts")
    if isinstance(parts, dict):
        for entry in parts.values():
            if isinstance(entry, dict) and isinstance(entry.get("digest"), str):
                digests.add(entry["digest"])
    return digests


def _record_digests(record: object) -> set[str]:
    """The blob digests that a stage cache record needs; raises for a malformed record."""
    if not isinstance(record, dict):
        raise TypeError("record is not an object")
    outputs = record["outputs"]
    if not isinstance(outputs, dict):
        raise TypeError("outputs is not an object")
    digests: set[str] = set()
    for value in outputs.values():
        digest = value.get("digest")
        if digest is not None:
            digests.add(str(digest))
        for part in value.get("parts") or []:
            digests.add(str(part[1]))
    return digests


def cache_probe(layout: StateLayout) -> dict[str, JsonValue]:
    """Cache statistics plus the free disk space of the state directory, for ``doctor``.

    ``free_bytes`` is ``None`` when the disk usage cannot be read.
    """
    stats = CacheAdmin(layout).stats()
    probe: dict[str, JsonValue] = {
        "blob_count": stats.blob_count,
        "blob_bytes": stats.blob_bytes,
        "stage_records": stats.stage_records,
        "item_entries": stats.item_entries,
        "item_bytes": stats.item_bytes,
        "scan_count": stats.scan_count,
        "tmp_files": stats.tmp_files,
        "free_bytes": None,
    }
    location = layout.root
    while not location.exists() and location.parent != location:
        location = location.parent
    with contextlib.suppress(OSError):
        probe["free_bytes"] = shutil.disk_usage(location).free
    return probe
