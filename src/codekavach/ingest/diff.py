"""Diff mode: reduce a scan to the files that changed since a base (E06-03).

Owning epic: E06.

The base is either a git ref (a branch, a tag or a commit, resolved in the scanned tree) or the id
of an earlier scan, whose stored per-file ``sha256`` values are compared with the current ones,
which makes the mode work for archive and stdin sources that have no history.

**Honesty.** A diff scan reviews fewer files, so the caller records the base and how many files
were left out (:class:`~codekavach.ingest.discovery.DiscoveryReport`). When the base cannot be
resolved this module returns ``None`` and the caller scans everything and says so: a silent empty
scan is the dangerous failure.

**Git.** ``git diff --name-status`` compares the working tree with the base and its paths are made
relative to the scanned directory (``--relative``), so a sub-directory of a repository works.
Files that are not yet tracked count as added. Renames are reported as a delete and an add
(``--no-renames``), and a deleted path is excluded from the scan because there is nothing to
analyse; ``include_deleted`` only changes whether the report counts them. The same hardened
switches as the clone apply, and no external diff or text-conversion program is run.
"""

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from codekavach.core.log import get_logger
from codekavach.core.models import RepoPath
from codekavach.core.pipeline import keys
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.base import ArtefactError
from codekavach.core.store.layout import StateLayout, StateLayoutError
from codekavach.ingest.models import SourceFile
from codekavach.ingest.sources.git import (
    HARDENING,
    GitRunner,
    check_ref,
    hardened_environment,
    run_git,
)

_log = get_logger("codekavach.ingest.diff")

GIT_TIMEOUT_SECONDS: Final = 60.0
_SCAN_ID: Final = re.compile(r"^scan_[0-9A-HJKMNP-TV-Z]{26}$")
_DELETED: Final = "D"


@dataclass(frozen=True, slots=True)
class DiffResult:
    """The paths that differ from the base; ``changed`` are added or modified."""

    base: str
    changed: frozenset[RepoPath]
    deleted: frozenset[RepoPath]


def is_scan_id(value: str) -> bool:
    """Whether ``value`` has the shape of a scan id (``scan_`` and 26 ULID characters)."""
    return _SCAN_ID.fullmatch(value) is not None


def _git(runner: GitRunner, git: str, root: Path, *arguments: str) -> tuple[int, bytes]:
    env = hardened_environment(os.environ)
    result = runner([git, *HARDENING, *arguments], env, root, GIT_TIMEOUT_SECONDS)
    return result.returncode, result.stdout


def _split(output: bytes) -> list[str]:
    return output.decode("utf-8", "surrogateescape").split("\0")


def _parse_name_status(output: bytes) -> tuple[set[RepoPath], set[RepoPath]]:
    tokens = _split(output)
    changed: set[RepoPath] = set()
    deleted: set[RepoPath] = set()
    index = 0
    while index + 1 < len(tokens):
        status, path = tokens[index], tokens[index + 1]
        index += 2
        if path:
            (deleted if status.startswith(_DELETED) else changed).add(path)
    return changed, deleted


def diff_against_ref(
    root: Path, since: str, *, runner: GitRunner = run_git, git: str = "git"
) -> DiffResult | None:
    """The paths below ``root`` that differ from git ref ``since``, or ``None`` if unresolvable."""
    try:
        base = check_ref(since)
    except ValueError:
        return None
    code, _ = _git(runner, git, root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}")
    if code != 0:
        return None
    code, listing = _git(
        runner,
        git,
        root,
        "diff",
        "--name-status",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--relative",
        "-z",
        base,
        "--",
    )
    if code != 0:
        return None
    changed, deleted = _parse_name_status(listing)
    code, untracked = _git(runner, git, root, "ls-files", "--others", "--exclude-standard", "-z")
    if code == 0:
        changed.update(path for path in _split(untracked) if path)
    return DiffResult(base=since, changed=frozenset(changed), deleted=frozenset(deleted))


def previous_hashes(state_dir: Path, scan_id: str) -> dict[RepoPath, str] | None:
    """Path to ``sha256`` of the files of an earlier scan, or ``None`` if its records are gone."""
    if not is_scan_id(scan_id):
        return None
    try:
        store = OnDiskArtefactStore.open_existing(StateLayout(state_dir), scan_id)
        files = store.get_list(keys.FILES, SourceFile)
    except (ArtefactError, StateLayoutError, OSError, ValueError):
        return None
    return {file.path: file.sha256 for file in files}


def diff_against_scan(
    since: str, previous: Mapping[RepoPath, str], current: Sequence[SourceFile]
) -> DiffResult:
    """Compare the current per-file hashes with those of the earlier scan ``since``."""
    now = {file.path: file.sha256 for file in current}
    changed = {path for path, digest in now.items() if previous.get(path) != digest}
    deleted = set(previous) - set(now)
    return DiffResult(base=since, changed=frozenset(changed), deleted=frozenset(deleted))


def resolve_diff(
    root: Path,
    since: str,
    files: Sequence[SourceFile],
    *,
    state_dir: Path | None = None,
    runner: GitRunner = run_git,
    git: str = "git",
) -> DiffResult | None:
    """Resolve ``since`` as a scan id or a git ref; ``None`` when neither gives a base."""
    if is_scan_id(since):
        previous = previous_hashes(state_dir, since) if state_dir is not None else None
        if previous is not None:
            return diff_against_scan(since, previous, files)
        _log.warning("diff_base_unresolved", kind="scan")
        return None
    result = diff_against_ref(root, since, runner=runner, git=git)
    if result is None:
        _log.warning("diff_base_unresolved", kind="ref")
    return result


def changed_paths(
    root: Path, since: str, *, runner: GitRunner = run_git, git: str = "git"
) -> set[RepoPath] | None:
    """The added and modified paths since git ref ``since``; ``None`` if it cannot be resolved."""
    result = diff_against_ref(root, since, runner=runner, git=git)
    return None if result is None else set(result.changed)
