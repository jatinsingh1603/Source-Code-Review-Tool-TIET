"""``run_scan`` over an archive, a git URL and standard input (E06-03).

The ingest and parse stages are real; the parse stage proves that later stages read the files
from the working root, not from the project directory. The working root is removed when the scan
ends unless ``keep_work`` is given, and a failed materialisation leaves nothing behind.
"""

import io
import socket
import sys
from pathlib import Path

import pytest

from codekavach.config import load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.ingest.models import SourceFile
from tests.support.hostile import commit_files, git, has_git, make_repo, tar_of, zip_of
from tests.support.ingest import SALT_HEX, stages_registry

SOURCES = {
    "app.py": "import os\n\n\ndef handler(request):\n    os.system(request.args['cmd'])\n",
    "lib/util.py": "def helper(value):\n    return value\n",
}


def scan(
    tmp_path: Path,
    target: str,
    *,
    options: dict[str, object] | None = None,
    keep_work: bool = False,
) -> ScanOutcome:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    loaded = load_settings(target=project, env={"CODEKAVACH_HOME": str(tmp_path / "home")})
    return run_scan(
        loaded,
        target,
        salt=ScanSalt.from_hex(SALT_HEX),
        registry=stages_registry("ingest", "parse"),
        persist=False,
        ingest_options=options,
        keep_work=keep_work,
    )


def store_of(outcome: ScanOutcome) -> OnDiskArtefactStore:
    return OnDiskArtefactStore.open_existing(StateLayout(outcome.state_dir), outcome.scan.id)


def files_of(outcome: ScanOutcome) -> list[str]:
    return [f.path for f in store_of(outcome).get_list(keys.FILES, SourceFile)]


def work_dir(outcome: ScanOutcome) -> Path:
    return StateLayout(outcome.state_dir).work_dir(str(outcome.scan.id))


@pytest.mark.parametrize("name", ["app.zip", "app.tar.gz"])
def test_an_archive_is_scanned_and_its_working_root_is_removed(tmp_path: Path, name: str) -> None:
    archive = (
        zip_of(tmp_path / name, SOURCES)
        if name.endswith(".zip")
        else tar_of(tmp_path / name, SOURCES, "w:gz")
    )
    outcome = scan(tmp_path, str(archive))
    assert outcome.scan.status is ScanStatus.COMPLETED
    assert files_of(outcome) == sorted(SOURCES)
    symbols = store_of(outcome).get_json(keys.SYMBOLS)
    assert "handler" in str(symbols)  # the parse stage read the extracted files
    assert not work_dir(outcome).exists()


def test_keep_work_leaves_the_working_root(tmp_path: Path) -> None:
    outcome = scan(tmp_path, str(zip_of(tmp_path / "a.zip", SOURCES)), keep_work=True)
    assert (work_dir(outcome) / "app.py").is_file()


def test_a_hostile_archive_fails_the_scan_and_leaves_no_working_root(tmp_path: Path) -> None:
    archive = tar_of(tmp_path / "evil.tar", {"../../escape.txt": "x", "ok.py": "x = 1\n"})
    outcome = scan(tmp_path, str(archive))
    assert outcome.scan.status is ScanStatus.FAILED
    assert not work_dir(outcome).exists()
    assert not (tmp_path / "escape.txt").exists()


def test_standard_input_is_scanned_as_one_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(SOURCES["app.py"].encode())))
    outcome = scan(tmp_path, "-", options={"stdin_filename": "hook.py"})
    assert outcome.scan.status is ScanStatus.COMPLETED
    assert files_of(outcome) == ["hook.py"]
    assert not work_dir(outcome).exists()


@pytest.mark.skipif(not has_git(), reason="git is not installed")
def test_a_git_url_is_cloned_scanned_and_diffed_against_a_tag(tmp_path: Path) -> None:
    remote = make_repo(tmp_path / "remote", SOURCES)
    git(remote, "tag", "v1")
    commit_files(remote, {"lib/util.py": "def helper(value):\n    return value + 1\n"}, "change")
    full = scan(tmp_path, remote.as_uri())
    assert full.scan.status is ScanStatus.COMPLETED
    assert files_of(full) == sorted(SOURCES)
    narrowed = scan(tmp_path, remote.as_uri(), options={"diff_since": "v1"})
    assert files_of(narrowed) == ["lib/util.py"]
    coverage = store_of(narrowed).get_json(keys.INGEST_COVERAGE)
    assert isinstance(coverage, dict)
    assert coverage["diff_base"] == "v1" and coverage["diff_excluded"] == 1
    assert not work_dir(narrowed).exists()


@pytest.mark.skipif(not has_git(), reason="git is not installed")
def test_an_unreachable_git_remote_fails_the_scan_cleanly(tmp_path: Path) -> None:
    outcome = scan(tmp_path, (tmp_path / "does-not-exist.git").as_uri())
    assert outcome.scan.status is ScanStatus.FAILED
    assert not work_dir(outcome).exists()


@pytest.mark.skipif(not has_git(), reason="git is not installed")
def test_a_repository_and_a_zip_of_the_same_tree_publish_the_same_files(tmp_path: Path) -> None:
    remote = make_repo(tmp_path / "remote", SOURCES)
    from_git = scan(tmp_path, remote.as_uri())
    from_zip = scan(tmp_path, str(zip_of(tmp_path / "same.zip", SOURCES)))
    git_files = store_of(from_git).get_list(keys.FILES, SourceFile)
    zip_files = store_of(from_zip).get_list(keys.FILES, SourceFile)
    assert git_files == zip_files
    assert [f.sha256 for f in git_files] == [f.sha256 for f in zip_files]


@pytest.mark.skipif(not has_git(), reason="git is not installed")
def test_a_git_ref_and_a_scan_id_select_the_same_files_for_the_same_change(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "repo", SOURCES)
    git(repo, "tag", "v1")
    baseline = scan(tmp_path, str(repo))
    commit_files(repo, {"lib/util.py": "def helper(value):\n    return value * 2\n"}, "change")
    by_ref = scan(tmp_path, str(repo), options={"diff_since": "v1"})
    by_scan = scan(tmp_path, str(repo), options={"diff_since": str(baseline.scan.id)})
    assert files_of(by_ref) == files_of(by_scan) == ["lib/util.py"]


def test_no_socket_is_opened_for_an_archive_or_a_local_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    local = tmp_path / "local"
    local.mkdir()
    (local / "a.py").write_text("x = 1\n", encoding="utf-8")
    for target in (str(zip_of(tmp_path / "n.zip", SOURCES)), str(local)):
        assert scan(tmp_path, target).scan.status is ScanStatus.COMPLETED
