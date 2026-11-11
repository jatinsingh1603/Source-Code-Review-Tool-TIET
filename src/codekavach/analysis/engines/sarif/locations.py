"""URI resolution and region conversion for SARIF locations (E14-02).

Owning epic: E14. A SARIF log is written by third-party code that has just read an attacker
influenced repository, so every URI is hostile (CWE-22): ``resolve_uri`` returns a path relative to
the scan root or ``None``, and never a path that leaves the root. ``SourceCache`` reads the files
the log refers to, from the read-only view, for line arithmetic and fingerprints.

Line arithmetic uses ``split_lines`` of ``core.models.text``, never ``str.splitlines``. SARIF
columns are 1-based with an exclusive end, the same convention as ``Location``. A log that does not
state ``columnKind`` is read as code-point columns; ``utf16CodeUnits`` is converted.
"""

import os
import posixpath
import re
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

from codekavach.analysis.engines.sarif.model import ArtifactLocation, Region, Run
from codekavach.core.models.location import Location
from codekavach.core.models.paths import RepoPath, normalise_repo_path
from codekavach.core.models.text import split_lines

DEFAULT_MOUNTS = ("/src",)
MAX_SOURCE_BYTES = 16 * 1024 * 1024
HEAD_BYTES = 4096
MAX_CACHED_FILES = 256
_MAX_BASE_DEPTH = 4
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]+:")
_DRIVE = re.compile(r"^[A-Za-z]:/")
_FILE_DRIVE = re.compile(r"^/[A-Za-z]:/")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_BACKSLASH = chr(92)


def _fold(text: str) -> str:
    """Case-fold on Windows, where paths ignore case; keep ``/`` separators (unlike normcase)."""
    return text.lower() if os.name == "nt" else text


@lru_cache(maxsize=64)
def _root_text(root: Path) -> str:
    return _fold(root.resolve().as_posix()).rstrip("/")


def _plain(uri: str) -> str | None:
    """The path part of ``uri`` with ``file:`` removed, percent-decoding done, ``/`` separators."""
    if uri[:5].lower() == "file:":
        parts = urlsplit(uri)
        if parts.netloc not in ("", "localhost"):
            return None
        text = unquote(parts.path)
        if _FILE_DRIVE.match(text):
            text = text[1:]
    elif _SCHEME.match(uri):
        return None
    else:
        text = unquote(uri)
    if _CONTROL.search(text):
        return None
    return text.replace(_BACKSLASH, "/")


def _is_absolute(text: str) -> bool:
    return text.startswith("/") or bool(_DRIVE.match(text))


def _under(text: str, prefix: str) -> str | None:
    """``text`` relative to ``prefix`` when it lies below it, else ``None``."""
    cleaned = posixpath.normpath(text)
    folded = _fold(cleaned)
    if folded == prefix:
        return ""
    if folded.startswith(prefix + "/"):
        return cleaned[len(prefix) + 1 :]
    return None


def _base_text(run: Run, base_id: str, depth: int = 0) -> str | None:
    """The textual base for ``base_id``: ``""`` when it is undefined (the scan root)."""
    base = run.original_uri_base_ids.get(base_id)
    if base is None or base.uri is None:
        return ""
    text = _plain(base.uri)
    if text is None:
        return None
    if base.uri_base_id and not _is_absolute(text) and depth < _MAX_BASE_DEPTH:
        parent = _base_text(run, base.uri_base_id, depth + 1)
        if parent is None:
            return None
        text = f"{parent.rstrip('/')}/{text}" if parent else text
    return text


def _artifact_uri(artifact: ArtifactLocation, run: Run) -> tuple[str | None, str | None]:
    if artifact.uri:
        return artifact.uri, artifact.uri_base_id
    index = artifact.index
    if index is not None and 0 <= index < len(run.artifacts):
        inner = run.artifacts[index].location
        if inner is not None and inner.uri:
            return inner.uri, artifact.uri_base_id or inner.uri_base_id
    return None, None


def _relative_to_known(text: str, base: str, root: Path, mounts: Sequence[str]) -> str | None:
    """The part of an absolute ``text`` below the root, a mount point or the stated base."""
    relative = _under(text, _root_text(root))
    for mount in mounts:
        if relative is None:
            relative = _under(text, _fold(mount.rstrip("/")))
    if relative is None and base and _is_absolute(base):
        # The base names somewhere other than our root: the part below it is the relative path.
        relative = _under(text, _fold(posixpath.normpath(base)))
    return relative


def resolve_uri(  # noqa: PLR0911 - one early return per way a URI turns out to be unusable
    artifact: ArtifactLocation,
    run: Run,
    root: Path,
    *,
    mounts: Sequence[str] = DEFAULT_MOUNTS,
) -> RepoPath | None:
    """Return the repo-relative path an artifact location names, or ``None`` if unusable.

    Handles ``uriBaseId`` and ``originalUriBaseIds``, ``file://`` URIs, percent-encoding, Windows
    separators and ``artifacts[]`` index references. An absolute path is accepted only below the
    scan root, a mount point of it (``mounts``) or the stated base. A path that leaves the root by
    ``..``, a foreign host and any other scheme give ``None``.
    """
    uri, base_id = _artifact_uri(artifact, run)
    if not uri:
        return None
    text = _plain(uri)
    if text is None:
        return None
    base = _base_text(run, base_id) if base_id else ""
    if base is None:
        return None
    if not _is_absolute(text) and base:
        text = f"{base.rstrip('/')}/{text}"
    if _is_absolute(text):
        relative = _relative_to_known(text, base, root, mounts)
        if relative is None:
            return None
        text = relative
    cleaned = posixpath.normpath(text)
    if cleaned in {"", "."} or cleaned == ".." or cleaned.startswith("../"):
        return None
    try:
        return normalise_repo_path(cleaned)
    except ValueError:
        return None


def _utf16_to_code_points(line: str, column: int) -> int:
    """Convert a 1-based UTF-16 code-unit column in ``line`` to a code-point column."""
    units = 0
    for index, char in enumerate(line):
        if units >= column - 1:
            return index + 1
        units += 2 if ord(char) > 0xFFFF else 1
    return len(line) + 1 + max(0, column - 1 - units)


def _column(line: str | None, column: int, column_kind: str | None) -> int:
    if line is not None and column_kind == "utf16CodeUnits":
        return _utf16_to_code_points(line, column)
    return column


def region_to_location(
    region: Region | None,
    path: RepoPath,
    lines: Sequence[str] | None,
    *,
    column_kind: str | None = None,
    symbol: str | None = None,
) -> Location:
    """Convert a SARIF region to a ``Location`` with code-point columns.

    ``lines`` is the file as ``split_lines`` gives it (or ``None`` when unknown). A missing region
    is the first line of the file. Raises ``ValueError`` when the region lies outside the file.
    """
    start = region.start_line if region and region.start_line else 1
    end = region.end_line if region and region.end_line else start
    end = max(end, start)
    if lines is not None:
        if start > max(len(lines), 1):
            raise ValueError("region starts after the end of the file")
        end = min(end, max(len(lines), 1))
    start_col: int | None = None
    end_col: int | None = None
    if region is not None and region.start_column:
        first = lines[start - 1] if lines else None
        last = lines[end - 1] if lines else None
        start_col = max(1, _column(first, region.start_column, column_kind))
        if region.end_column:
            end_col = max(1, _column(last, region.end_column, column_kind))
        elif last is not None:
            end_col = len(last) + 1
        else:
            start_col = None
        if start_col is not None and end_col is not None and start == end:
            end_col = max(end_col, start_col)
    return Location(
        path=path,
        start_line=start,
        end_line=end,
        start_col=start_col,
        end_col=end_col if start_col is not None else None,
        symbol=symbol,
    )


class SourceCache:
    """Reads files of the scan root for line arithmetic, fingerprints and language detection."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._resolved = root.resolve()
        self._lines: dict[str, list[str] | None] = {}
        self._heads: dict[str, bytes] = {}

    def lines(self, path: str) -> list[str] | None:
        """The file's lines, or ``None`` when it is missing, unreadable or outside the root."""
        if path in self._lines:
            return self._lines[path]
        if len(self._lines) >= MAX_CACHED_FILES:
            self._lines.clear()
            self._heads.clear()
        data = self._read(path)
        if data is None:
            self._lines[path] = None
            return None
        self._heads[path] = data[:HEAD_BYTES]
        result = split_lines(data.decode("utf-8", errors="replace"))
        self._lines[path] = result
        return result

    def head(self, path: str) -> bytes:
        """The first bytes of the file (empty when unreadable)."""
        self.lines(path)
        return self._heads.get(path, b"")

    def _read(self, path: str) -> bytes | None:
        target = self._root / path
        try:
            if not target.is_file() or not target.resolve().is_relative_to(self._resolved):
                return None
            if target.stat().st_size > MAX_SOURCE_BYTES:
                return None
            return target.read_bytes()
        except OSError:
            return None
