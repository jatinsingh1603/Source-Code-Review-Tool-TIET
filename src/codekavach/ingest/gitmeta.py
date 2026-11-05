"""Commit, branch and dirtiness of the scanned repository, without its remote (E06-02).

Owning epic: E06.

The commit and the branch are read straight from ``.git/HEAD``, the ref file it points at and
``packed-refs``; no ``git`` process is needed for them. ``.git/config`` is never opened, so the
remote URL (it names the client, the vendor and often an internal host, and would be the cheapest
re-identification for adversary A1) cannot reach a model field, a log line or an artefact. The
dirty flag needs ``git status`` and is therefore captured only on request, and ``None`` means
"not known", never "clean".

``git`` is an untrusted-repository execution vector (CVE-2024-32002, hooks, ``core.fsmonitor``),
so it runs with hooks and fsmonitor switched off, without optional locks and without a prompt.
Everything in ``.git`` is attacker-controlled: names are validated, reads are size-bounded and a
ref that resolves outside the git directory is ignored.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import ClassVar, Final

from codekavach.core.log import get_logger
from codekavach.core.models import DataClassification, KavachModel

_log = get_logger("codekavach.ingest.gitmeta")

HEAD_FILE_MAX_BYTES: Final = 4096
PACKED_REFS_MAX_BYTES: Final = 16 * 1024 * 1024
STATUS_TIMEOUT_SECONDS: Final = 30.0
MAX_BRANCH_LENGTH: Final = 255

_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REF_NAME = re.compile(r"^refs/[A-Za-z0-9._/+@-]{1,500}$")
_HEADS = "refs/heads/"


class GitMetadata(KavachModel):
    """What the report may say about the repository's state; each field is ``None`` if unknown.

    Branch names can identify a client or a ticket, so the model is classified as raw.
    """

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    commit: str | None = None
    branch: str | None = None
    dirty: bool | None = None


def _read_small(path: Path, limit: int) -> str | None:
    """The text of a regular file of at most ``limit`` bytes, or ``None``."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None


def _git_dir(root: Path) -> Path | None:
    """``root/.git`` as a directory, following a ``gitdir:`` file (worktree, submodule)."""
    dot_git = root / ".git"
    try:
        if dot_git.is_dir() and not dot_git.is_symlink():
            return dot_git
    except OSError:
        return None
    text = _read_small(dot_git, HEAD_FILE_MAX_BYTES)
    if text is None or not text.startswith("gitdir:"):
        return None
    target = Path(text.removeprefix("gitdir:").strip())
    candidate = target if target.is_absolute() else root / target
    try:
        return candidate if candidate.is_dir() else None
    except OSError:
        return None


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except (OSError, ValueError):
        return False
    return True


def _packed_ref(git_dir: Path, ref: str) -> str | None:
    packed = git_dir / "packed-refs"
    try:
        if packed.is_symlink() or not packed.is_file():
            return None
        if packed.stat().st_size > PACKED_REFS_MAX_BYTES:
            return None
        with packed.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith(("#", "^")):
                    continue
                digest, _, name = line.strip().partition(" ")
                if name == ref and _COMMIT.match(digest):
                    return digest
    except OSError:
        return None
    return None


def _resolve_ref(git_dir: Path, ref: str) -> str | None:
    if not _REF_NAME.match(ref) or ".." in ref.split("/"):
        return None
    ref_file = git_dir / ref
    if _inside(ref_file, git_dir):
        text = _read_small(ref_file, HEAD_FILE_MAX_BYTES)
        if text is not None and _COMMIT.match(text.strip()):
            return text.strip()
    return _packed_ref(git_dir, ref)


def _commit_and_branch(git_dir: Path) -> tuple[str | None, str | None]:
    head = _read_small(git_dir / "HEAD", HEAD_FILE_MAX_BYTES)
    if head is None:
        return None, None
    head = head.strip()
    if _COMMIT.match(head):
        return head, None  # detached HEAD: the hash, no branch
    if not head.startswith("ref:"):
        return None, None
    ref = head.removeprefix("ref:").strip()
    branch = ref.removeprefix(_HEADS) if ref.startswith(_HEADS) else None
    if branch is not None and (not branch or len(branch) > MAX_BRANCH_LENGTH):
        branch = None
    return _resolve_ref(git_dir, ref), branch


def _is_dirty(root: Path, timeout: float) -> bool | None:
    git = shutil.which("git")
    if git is None:
        return None
    command = [
        git,
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.fsmonitor=false",
        "--no-optional-locks",
        "-C",
        str(root),
        "status",
        "--porcelain",
    ]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        _log.debug("git_status_unavailable")
        return None
    if completed.returncode != 0:
        _log.debug("git_status_failed", returncode=completed.returncode)
        return None
    return bool(completed.stdout.strip())


def read_git_metadata(
    root: Path, *, check_dirty: bool = False, timeout: float = STATUS_TIMEOUT_SECONDS
) -> GitMetadata:
    """The commit, branch and (when ``check_dirty``) dirtiness of the repository at ``root``.

    A directory that is not a git repository, or a repository that cannot be read, gives
    all-``None`` metadata; this never raises. The remote URL is not read.
    """
    git_dir = _git_dir(root)
    if git_dir is None:
        return GitMetadata()
    commit, branch = _commit_and_branch(git_dir)
    dirty = _is_dirty(root, timeout) if check_dirty else None
    return GitMetadata(commit=commit, branch=branch, dirty=dirty)
