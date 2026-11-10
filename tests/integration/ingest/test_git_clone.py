"""Real ``git`` against repositories on the local file system (E06-03).

The network is not used: every remote is a ``file://`` URL of a repository created in ``tmp_path``.
"""

from pathlib import Path

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.ingest.diff import changed_paths, diff_against_ref
from codekavach.ingest.gitmeta import unfetched_submodules
from codekavach.ingest.limits import IngestLimits
from codekavach.ingest.sources.base import UnsupportedSource
from codekavach.ingest.sources.git import GitSource
from tests.support.hostile import add_gitlink, all_files, commit_files, git, has_git, make_repo

pytestmark = pytest.mark.skipif(not has_git(), reason="git is not installed")


def limits() -> IngestLimits:
    return IngestLimits.from_settings(IngestSettings())


@pytest.fixture
def remote(tmp_path: Path) -> Path:
    repo = make_repo(
        tmp_path / "remote", {"a.py": "a = 1\n", "b.py": "b = 1\n", "docs/readme.md": "# r\n"}
    )
    git(repo, "tag", "v1")
    commit_files(repo, {"a.py": "a = 2\n", "c.py": "c = 1\n"}, "second")
    return repo


def clone(remote: Path, tmp_path: Path, **options: object) -> Path:
    source = GitSource(**options)  # type: ignore[arg-type]
    return source.materialise(remote.as_uri(), limits=limits(), into=tmp_path / "work" / "tree")


def test_a_shallow_clone_has_the_files_and_one_commit(remote: Path, tmp_path: Path) -> None:
    root = clone(remote, tmp_path)
    assert all_files(root / "docs") == ["readme.md"]
    assert (root / "a.py").read_text(encoding="utf-8") == "a = 2\n"
    assert git(root, "rev-list", "--count", "HEAD") == "1"
    assert (root / ".git").is_dir()


def test_a_ref_selects_a_tag(remote: Path, tmp_path: Path) -> None:
    root = clone(remote, tmp_path, ref="v1")
    assert (root / "a.py").read_text(encoding="utf-8") == "a = 1\n"
    assert not (root / "c.py").exists()


def test_a_commit_ref_is_checked_out(remote: Path, tmp_path: Path) -> None:
    first = git(remote, "rev-parse", "v1^{commit}")
    root = clone(remote, tmp_path, ref=first)
    assert (root / "a.py").read_text(encoding="utf-8") == "a = 1\n"
    assert git(root, "rev-parse", "HEAD") == first


def test_an_unknown_ref_fails_and_leaves_no_working_root(remote: Path, tmp_path: Path) -> None:
    with pytest.raises(UnsupportedSource):
        clone(remote, tmp_path, ref="no-such-branch")
    assert not (tmp_path / "work" / "tree").exists()


def test_symlinks_are_checked_out_as_plain_files(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "linky", {"real.txt": "target\n"})
    try:
        (repo / "link.txt").symlink_to("real.txt")
    except OSError:
        pytest.skip("symbolic links are not permitted here")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "link")
    root = GitSource().materialise(repo.as_uri(), limits=limits(), into=tmp_path / "w" / "t")
    assert not (root / "link.txt").is_symlink()
    assert (root / "link.txt").read_text(encoding="utf-8") == "real.txt"


def test_a_submodule_is_not_fetched_and_is_recorded(tmp_path: Path) -> None:
    library = make_repo(tmp_path / "library", {"lib.py": "SECRET_LIBRARY = 1\n"})
    app = make_repo(tmp_path / "app", {"main.py": "import lib\n"})
    add_gitlink(app, "vendor/lib", library.as_uri())
    root = GitSource().materialise(app.as_uri(), limits=limits(), into=tmp_path / "w" / "t")
    assert (root / "main.py").exists()
    assert not (root / "vendor" / "lib" / "lib.py").exists()
    assert unfetched_submodules(root) == ("vendor/lib",)
    assert not (root / ".git" / "modules").exists()


def test_diff_against_a_tag_lists_added_modified_and_deleted(remote: Path) -> None:
    (remote / "b.py").unlink()
    (remote / "untracked.py").write_text("u = 1\n", encoding="utf-8")
    result = diff_against_ref(remote, "v1")
    assert result is not None
    assert result.changed == {"a.py", "c.py", "untracked.py"}
    assert result.deleted == {"b.py"}
    assert changed_paths(remote, "v1") == {"a.py", "c.py", "untracked.py"}


def test_diff_paths_are_relative_to_the_scanned_directory(remote: Path) -> None:
    commit_files(remote, {"docs/new.md": "n\n", "docs/readme.md": "# changed\n"}, "docs")
    result = diff_against_ref(remote / "docs", "v1")
    assert result is not None
    assert result.changed == {"new.md", "readme.md"}


def test_a_renamed_file_is_a_delete_and_an_add(remote: Path) -> None:
    git(remote, "mv", "b.py", "renamed.py")
    git(remote, "commit", "-q", "-m", "rename")
    result = diff_against_ref(remote, "v1")
    assert result is not None
    assert "renamed.py" in result.changed and "b.py" in result.deleted


@pytest.mark.parametrize("since", ["nope", "--output=/tmp/x", "refs/../x", "", "a b"])
def test_an_unresolvable_or_dangerous_base_gives_none(remote: Path, since: str) -> None:
    assert diff_against_ref(remote, since) is None
    assert changed_paths(remote, since) is None


def test_a_directory_that_is_not_a_repository_gives_none(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    assert changed_paths(plain, "main") is None


def test_the_base_of_a_diff_is_fetched_into_a_shallow_clone(remote: Path, tmp_path: Path) -> None:
    root = clone(remote, tmp_path, fetch_base="v1")
    result = diff_against_ref(root, "v1")
    assert result is not None
    assert result.changed == {"a.py", "c.py"}


def test_without_fetching_the_base_a_shallow_clone_cannot_resolve_a_tag(
    remote: Path, tmp_path: Path
) -> None:
    root = clone(remote, tmp_path)
    assert diff_against_ref(root, "v1") is None
