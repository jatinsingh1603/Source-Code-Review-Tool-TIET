"""The layout of the state directory and the only way E04 creates directories and writes files.

Owning epic: E04.

::

    <state_dir>/
      .gitignore                                "*"
      cache/blobs/<aa>/<sha256>                 content-addressed artefact blobs (E04-09)
      cache/stages/<aa>/<stage_key>.json        stage cache records (E04-21)
      cache/items/<namespace>/<aa>/<key>.json   per-item memo entries (E04-22)
      scans/<scan_id>/index/<key>.json          logical key -> blob binding (E04-09)
      scans/<scan_id>/manifest.json             (E04-24)
      scans/<scan_id>/config-snapshot.json
      scans/<scan_id>/checkpoint.json           (E04-28)
      codekavach.db                             local database (E04-25)

Everything below the state directory may contain client code in the clear. Controls: every
caller-supplied path component is validated and every path is contained in the root; directories
are created 0o700 and files 0o600 (POSIX); writes are atomic through a temporary file opened with
``O_EXCL`` and ``O_NOFOLLOW`` in the target directory; the directory ignores itself in git.
Other epics add ``vault/`` and ``ledger/`` next to ``cache/`` and ``scans/``.
"""

import contextlib
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from codekavach.config.errors import ConfigError
from codekavach.config.paths import default_database_path, ensure_state_dir
from codekavach.core.pipeline.errors import PipelineError
from codekavach.core.pipeline.keys import is_valid_key

DIR_MODE = 0o700
FILE_MODE = 0o600
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SCAN_ID = re.compile(r"^scan_[0-9A-HJKMNP-TV-Z]{26}$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


class StateLayoutError(PipelineError):
    """A state path is invalid, escapes the state directory or is unsafe."""


def secure_mkdir(path: Path) -> Path:
    """Create ``path`` and every missing parent with mode 0o700; refuse a symlink or a file."""
    missing: list[Path] = []
    current = path
    while not os.path.lexists(current) and current.parent != current:
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        with contextlib.suppress(FileExistsError):
            directory.mkdir(mode=DIR_MODE)
    if path.is_symlink() or not path.is_dir():
        raise StateLayoutError(f"{path} is a symbolic link or not a directory")
    return path


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically with mode 0o600, never following a symlink."""
    secure_mkdir(path.parent)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _component(pattern: re.Pattern[str], value: object, what: str) -> str:
    # fullmatch: ``$`` would also accept a trailing newline, which must not reach a file name.
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise StateLayoutError(f"invalid {what}")
    return value


@dataclass(frozen=True, slots=True)
class StateLayout:
    """Typed paths below one state directory."""

    root: Path

    def contain(self, path: Path) -> Path:
        """``path`` made absolute, provided it lies inside the root.

        The check is lexical (``..`` collapsed) for every path and, for a path that already
        exists, is repeated on the real path so that a symlink cannot lead outside the root.
        Real paths are not compared for paths still being created, because on Windows their
        resolved form can change while another thread creates the parent directories.
        """
        root = Path(os.path.abspath(self.root))  # noqa: PTH100 - lexical on purpose
        candidate = Path(os.path.abspath(path))  # noqa: PTH100 - lexical on purpose
        if not candidate.is_relative_to(root):
            raise StateLayoutError("path resolves outside the state directory")
        if os.path.lexists(candidate) and not candidate.resolve().is_relative_to(
            self.root.resolve()
        ):
            raise StateLayoutError("path resolves outside the state directory")
        return candidate

    def ensure(self) -> "StateLayout":
        """Create or tighten the root (0o700, self-ignoring ``.gitignore``); refuse a symlink."""
        try:
            ensure_state_dir(self.root)
        except ConfigError as error:
            raise StateLayoutError(str(error)) from None
        return self

    @property
    def blobs_dir(self) -> Path:
        """Content-addressed artefact blobs."""
        return self.root / "cache" / "blobs"

    def blob_path(self, digest: str) -> Path:
        """The blob with this SHA-256 digest."""
        digest = _component(_HEX64, digest, "digest")
        return self.contain(self.blobs_dir / digest[:2] / digest)

    def stage_record_path(self, stage_key: str) -> Path:
        """The stage cache record for ``stage_key``."""
        stage_key = _component(_HEX64, stage_key, "stage key")
        return self.contain(self.root / "cache" / "stages" / stage_key[:2] / f"{stage_key}.json")

    def items_dir(self, namespace: str) -> Path:
        """Per-item memo entries of one namespace."""
        namespace = _component(_NAMESPACE, namespace, "namespace")
        if ".." in namespace:
            raise StateLayoutError("invalid namespace")
        return self.contain(self.root / "cache" / "items" / namespace)

    def item_path(self, namespace: str, item_key: str) -> Path:
        """One memo entry."""
        item_key = _component(_HEX64, item_key, "item key")
        return self.contain(self.items_dir(namespace) / item_key[:2] / f"{item_key}.json")

    @property
    def scans_dir(self) -> Path:
        """Per-scan records."""
        return self.root / "scans"

    def scan_dir(self, scan_id: str) -> Path:
        """The records of one scan."""
        scan_id = _component(_SCAN_ID, scan_id, "scan id")
        return self.contain(self.scans_dir / scan_id)

    def index_dir(self, scan_id: str) -> Path:
        """Logical key to blob bindings of one scan."""
        return self.contain(self.scan_dir(scan_id) / "index")

    def index_path(self, scan_id: str, key: str) -> Path:
        """The binding of one artefact key."""
        if not is_valid_key(key):
            raise StateLayoutError("invalid artefact key")
        return self.contain(self.index_dir(scan_id) / f"{key}.json")

    def manifest_path(self, scan_id: str) -> Path:
        """The scan manifest."""
        return self.contain(self.scan_dir(scan_id) / "manifest.json")

    def snapshot_path(self, scan_id: str) -> Path:
        """The configuration snapshot of a scan."""
        return self.contain(self.scan_dir(scan_id) / "config-snapshot.json")

    def checkpoint_path(self, scan_id: str) -> Path:
        """The resume checkpoint of a scan."""
        return self.contain(self.scan_dir(scan_id) / "checkpoint.json")

    @property
    def db_path(self) -> Path:
        """The local SQLite database."""
        return default_database_path(self.root)
