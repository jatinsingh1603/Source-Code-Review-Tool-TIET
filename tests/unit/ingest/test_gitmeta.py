"""``read_git_metadata``: refs read from ``.git`` directly, the remote never read (E06-02)."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codekavach.ingest import gitmeta
from codekavach.ingest.gitmeta import GitMetadata, read_git_metadata

COMMIT = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
OTHER = "fedcba9876543210fedcba9876543210fedcba98"  # pragma: allowlist secret
REMOTE_HOST = "git.client-bank.example.invalid"


def _repo(root: Path, head: str, *, ref_file: str | None = None, packed: str = "") -> Path:
    git_dir = root / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "HEAD").write_text(head, encoding="utf-8")
    (git_dir / "config").write_text(
        f'[remote "origin"]\n\turl = https://{REMOTE_HOST}/team/repo.git\n', encoding="utf-8"
    )
    if ref_file is not None:
        ref_path = git_dir / "refs" / "heads" / "main"
        ref_path.parent.mkdir(parents=True)
        ref_path.write_text(ref_file, encoding="utf-8")
    if packed:
        (git_dir / "packed-refs").write_text(packed, encoding="utf-8")
    return root


def test_normal_branch(tmp_path: Path) -> None:
    root = _repo(tmp_path, "ref: refs/heads/main\n", ref_file=COMMIT + "\n")
    assert read_git_metadata(root) == GitMetadata(commit=COMMIT, branch="main", dirty=None)


def test_branch_names_with_slashes(tmp_path: Path) -> None:
    root = _repo(tmp_path, "ref: refs/heads/feature/login\n")
    ref = root / ".git" / "refs" / "heads" / "feature" / "login"
    ref.parent.mkdir(parents=True)
    ref.write_text(COMMIT, encoding="utf-8")
    assert read_git_metadata(root).branch == "feature/login"


def test_detached_head_gives_the_hash_and_no_branch(tmp_path: Path) -> None:
    root = _repo(tmp_path, COMMIT + "\n")
    assert read_git_metadata(root) == GitMetadata(commit=COMMIT, branch=None, dirty=None)


def test_packed_ref_is_used_when_there_is_no_ref_file(tmp_path: Path) -> None:
    packed = (
        f"# pack-refs with: peeled\n{OTHER} refs/heads/other\n{COMMIT} refs/heads/main\n^{OTHER}\n"
    )
    root = _repo(tmp_path, "ref: refs/heads/main\n", packed=packed)
    assert read_git_metadata(root) == GitMetadata(commit=COMMIT, branch="main", dirty=None)


def test_a_loose_ref_wins_over_a_packed_one(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        "ref: refs/heads/main\n",
        ref_file=COMMIT,
        packed=f"{OTHER} refs/heads/main\n",
    )
    assert read_git_metadata(root).commit == COMMIT


def test_an_unborn_branch_has_a_name_and_no_commit(tmp_path: Path) -> None:
    root = _repo(tmp_path, "ref: refs/heads/main\n")
    assert read_git_metadata(root) == GitMetadata(commit=None, branch="main", dirty=None)


def test_a_directory_that_is_not_a_repository_gives_all_none(tmp_path: Path) -> None:
    assert read_git_metadata(tmp_path) == GitMetadata()
    assert read_git_metadata(tmp_path / "missing") == GitMetadata()


def test_a_worktree_style_gitdir_file_is_followed(tmp_path: Path) -> None:
    real = tmp_path / "real-git-dir"
    real.mkdir()
    (real / "HEAD").write_text(COMMIT, encoding="utf-8")
    root = tmp_path / "work"
    root.mkdir()
    (root / ".git").write_text(f"gitdir: {real}\n", encoding="utf-8")
    assert read_git_metadata(root).commit == COMMIT


@pytest.mark.parametrize(
    "head",
    [
        "",
        "garbage\n",
        "ref: refs/heads/../../../etc/passwd\n",
        "ref: ../outside\n",
        "ref: refs/heads/a b\n",
        "ZZ" * 20 + "\n",
        COMMIT[:-1] + "\n",
    ],
)
def test_hostile_or_malformed_head_never_raises_and_gives_no_commit(
    tmp_path: Path, head: str
) -> None:
    root = _repo(tmp_path, head)
    assert read_git_metadata(root).commit is None


def test_a_ref_that_is_not_a_hash_is_ignored(tmp_path: Path) -> None:
    root = _repo(tmp_path, "ref: refs/heads/main\n", ref_file="not-a-hash\n")
    assert read_git_metadata(root).commit is None


def test_an_oversized_head_file_is_ignored(tmp_path: Path) -> None:
    root = _repo(tmp_path, "ref: refs/heads/" + "a" * (gitmeta.HEAD_FILE_MAX_BYTES + 1))
    assert read_git_metadata(root) == GitMetadata()


def test_an_overlong_branch_name_is_dropped(tmp_path: Path) -> None:
    name = "b" * (gitmeta.MAX_BRANCH_LENGTH + 1)
    root = _repo(tmp_path, f"ref: refs/heads/{name}\n")
    assert read_git_metadata(root).branch is None


def test_the_remote_is_in_no_field_and_the_config_is_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path, "ref: refs/heads/main\n", ref_file=COMMIT)
    opened: list[str] = []
    real_read_text = Path.read_text

    def spy(self: Path, *args: object, **kwargs: object) -> str:
        opened.append(self.name)
        return real_read_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", spy)
    metadata = read_git_metadata(root)
    assert "config" not in opened
    assert REMOTE_HOST not in metadata.model_dump_json()


# --- dirtiness, with a real git ---------------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _git(root: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)  # noqa: S607


@needs_git
def test_dirty_is_reported_only_when_asked_and_matches_the_tree(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "a.py")
    _git(tmp_path, "commit", "-q", "-m", "init")

    assert read_git_metadata(tmp_path).dirty is None
    clean = read_git_metadata(tmp_path, check_dirty=True)
    assert clean.dirty is False
    assert clean.branch == "main"
    assert clean.commit is not None
    assert len(clean.commit) == 40

    (tmp_path / "a.py").write_text("x = 2\n", encoding="utf-8")
    assert read_git_metadata(tmp_path, check_dirty=True).dirty is True


@needs_git
def test_untracked_files_make_the_tree_dirty(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "new.py").write_text("x = 1\n", encoding="utf-8")
    assert read_git_metadata(tmp_path, check_dirty=True).dirty is True


@needs_git
def test_git_runs_with_hooks_and_fsmonitor_off_and_no_optional_locks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(tmp_path, "init", "-q", "-b", "main")
    seen: list[list[str]] = []
    real_run = subprocess.run

    def spy(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        seen.append(command)
        return real_run(command, **kwargs)  # type: ignore[no-any-return, call-overload]

    monkeypatch.setattr(subprocess, "run", spy)
    read_git_metadata(tmp_path, check_dirty=True)
    (command,) = seen
    assert f"core.hooksPath={os.devnull}" in command
    assert "core.fsmonitor=false" in command
    assert "--no-optional-locks" in command


def test_dirty_is_none_when_git_is_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _repo(tmp_path, COMMIT)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert read_git_metadata(root, check_dirty=True) == GitMetadata(
        commit=COMMIT, branch=None, dirty=None
    )


def test_dirty_is_none_when_git_status_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _repo(tmp_path, COMMIT)

    def failing(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(shutil, "which", lambda _name: "git")
    monkeypatch.setattr(subprocess, "run", failing)
    assert read_git_metadata(root, check_dirty=True).dirty is None
