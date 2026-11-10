"""Helpers for the working root a source materialises into (E06-03).

Owning epic: E06.

The working root is a private (``0700``) directory under the state directory, named by the scan.
It is removed on success and on failure; removal tolerates the read-only files git leaves in
``.git`` (a plain ``rmtree`` fails on them on Windows).
"""

import os
import shutil
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from codekavach.core.log import get_logger

_log = get_logger("codekavach.ingest.sources.workdir")


def _make_writable_and_retry(function: Callable[[str], Any], path: str, _error: object) -> None:
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)  # noqa: PTH101
        function(path)
    except OSError:
        _log.debug("workdir_entry_left")


def remove_tree(path: Path) -> None:
    """Delete ``path`` and everything below it; a missing path and a stubborn entry are ignored."""
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        path.unlink(missing_ok=True)
        return
    shutil.rmtree(path, onexc=_make_writable_and_retry)


def private_directory(path: Path) -> Path:
    """Create ``path`` (and missing parents) with mode ``0700`` where the platform has modes."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        _log.debug("workdir_mode_unchanged")
    return path
