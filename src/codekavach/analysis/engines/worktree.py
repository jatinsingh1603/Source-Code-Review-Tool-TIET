"""A read-only view of the scan root for an engine (E14-01).

Owning epic: E14.

``materialise_readonly`` copies the regular files of the scan root into a private directory and
marks the copy read-only, so an engine cannot change the client's tree even if it tries: the
original is never opened for writing. Symbolic links are not followed or copied (CWE-59), and the
``.git`` directory is left out. ``neutralise_repo_config`` then moves the engine configuration
files the repository ships (an ESLint configuration, a Ruby style file, a scanner ignore file) out
of the view, because an engine may execute or honour such a file and the adapter passes its own
configuration explicitly (``docs/research/INSIGHTS.md`` section 7). Hiding in the copy, not
deleting in the original, keeps the original tree untouched.

Read-only is enforced with file modes. That holds against an engine running as the same user that
does not change modes itself; it is not a security boundary against a hostile engine, which is what
the container sandbox is for.
"""

import fnmatch
import os
import shutil
import stat
from pathlib import Path
from typing import Final

from codekavach.analysis.engines.base import EngineSpec
from codekavach.core.log import get_logger

SKIPPED_DIRECTORIES: Final = frozenset({".git"})
HIDDEN_DIRECTORY: Final = "hidden-config"
_FILE_MODE: Final = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
_DIR_MODE: Final = _FILE_MODE | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
_WRITABLE: Final = stat.S_IRWXU

_log = get_logger("codekavach.analysis.engines.worktree")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def materialise_readonly(root: Path, *, into: Path) -> Path:
    """Copy the regular files of ``root`` below ``into / "src"`` and make the copy read-only.

    Returns the view. ``into`` must exist and be outside ``root``.

    Raises:
        ValueError: ``into`` is inside ``root``.
    """
    root = root.resolve()
    if _inside(into, root):
        raise ValueError("the view must be created outside the scan root")
    view = into / "src"
    view.mkdir(parents=True, exist_ok=True)
    skipped_links = 0
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d not in SKIPPED_DIRECTORIES)
        base = Path(current)
        relative = base.relative_to(root)
        for directory in list(directories):
            if (base / directory).is_symlink():
                directories.remove(directory)
                skipped_links += 1
        target_dir = view / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in sorted(names):
            source = base / name
            if source.is_symlink() or not source.is_file():
                skipped_links += 1
                continue
            shutil.copyfile(source, target_dir / name)
    if skipped_links:
        _log.debug("engine_view_skipped_links", count=skipped_links)
    lock(view)
    return view


def lock(view: Path) -> None:
    """Make every file and directory of ``view`` read-only."""
    for current, directories, names in os.walk(view, topdown=False):
        base = Path(current)
        for name in names:
            (base / name).chmod(_FILE_MODE)
        for directory in directories:
            (base / directory).chmod(_DIR_MODE)
    view.chmod(_DIR_MODE)


def unlock(view: Path) -> None:
    """Make ``view`` writable again so that it can be removed."""
    if not view.exists():
        return
    for current, directories, names in os.walk(view):
        base = Path(current)
        base.chmod(_WRITABLE)
        for name in names:
            (base / name).chmod(_WRITABLE)
        for directory in directories:
            (base / directory).chmod(_WRITABLE)


def remove_view(into: Path) -> None:
    """Delete a view directory made by :func:`materialise_readonly`, read-only files included."""
    unlock(into)
    shutil.rmtree(into, ignore_errors=True)


def neutralise_repo_config(view: Path, spec: EngineSpec) -> list[str]:
    """Move the engine's own configuration files out of ``view``; returns their relative paths.

    The files go to a directory next to the view, never into it. A name in
    ``spec.config_filenames`` may be a ``fnmatch`` pattern such as ``.eslintrc*``.
    """
    if not spec.config_filenames:
        return []
    hidden_root = view.parent / HIDDEN_DIRECTORY / spec.id
    hidden: list[str] = []
    for current, directories, names in os.walk(view):
        directories.sort()
        base = Path(current)
        matches = sorted(
            name
            for name in names
            if any(fnmatch.fnmatchcase(name, pattern) for pattern in spec.config_filenames)
        )
        if not matches:
            continue
        base.chmod(_WRITABLE)
        try:
            for name in matches:
                relative = (base / name).relative_to(view)
                destination = hidden_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(base / name), str(destination))
                hidden.append(relative.as_posix())
        finally:
            base.chmod(_DIR_MODE)
    return sorted(hidden)
