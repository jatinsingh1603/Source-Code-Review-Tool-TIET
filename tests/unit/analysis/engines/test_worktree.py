"""The read-only source view and the hiding of repository-supplied engine config (E14-01)."""

import json
import os
import sys
from pathlib import Path

import pytest

from codekavach.analysis.engines.base import OUTPUT_TOKEN, ROOT_TOKEN
from codekavach.analysis.engines.sandbox import SandboxRequest, SubprocessSandbox
from codekavach.analysis.engines.worktree import (
    HIDDEN_DIRECTORY,
    materialise_readonly,
    neutralise_repo_config,
    remove_view,
)
from tests.support.engines import FAKE_ENGINE, make_spec

running_as_root = hasattr(os, "geteuid") and os.geteuid() == 0


def make_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (root / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")
    (root / "src" / "pkg" / "util.py").write_text("x = 1\n", encoding="utf-8")
    (root / ".fakerc").write_text("{}", encoding="utf-8")
    (root / "src" / ".fakerc.json").write_text("{}", encoding="utf-8")
    return root


def view_of(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = make_tree(tmp_path)
    into = tmp_path / "scratch"
    into.mkdir()
    return root, into, materialise_readonly(root, into=into)


def test_the_view_holds_the_regular_files_and_not_git(tmp_path: Path) -> None:
    _, _, view = view_of(tmp_path)
    found = sorted(p.relative_to(view).as_posix() for p in view.rglob("*") if p.is_file())
    assert found == [".fakerc", "src/.fakerc.json", "src/app.py", "src/pkg/util.py"]


def test_the_view_is_read_only_and_the_original_is_untouched(tmp_path: Path) -> None:
    root, _, view = view_of(tmp_path)
    with pytest.raises(PermissionError):
        (view / "src" / "app.py").write_text("changed", encoding="utf-8")
    assert (root / "src" / "app.py").read_text(encoding="utf-8") == "print(1)\n"
    (root / "src" / "app.py").write_text("still writable", encoding="utf-8")


@pytest.mark.skipif(sys.platform == "win32" or running_as_root, reason="directory modes")
def test_a_new_file_cannot_be_created_in_the_view(tmp_path: Path) -> None:
    _, _, view = view_of(tmp_path)
    with pytest.raises(PermissionError):
        (view / "src" / "new.py").write_text("x", encoding="utf-8")


def test_symbolic_links_are_not_followed(tmp_path: Path) -> None:
    root = make_tree(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        (root / "link.txt").symlink_to(outside)
        (root / "linked-dir").symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not available here")
    into = tmp_path / "scratch"
    into.mkdir()
    view = materialise_readonly(root, into=into)
    assert not (view / "link.txt").exists()
    assert not (view / "linked-dir").exists()


def test_a_view_inside_the_root_is_refused(tmp_path: Path) -> None:
    root = make_tree(tmp_path)
    with pytest.raises(ValueError, match="outside"):
        materialise_readonly(root, into=root / "scratch")


def test_config_files_are_hidden_by_name_and_pattern(tmp_path: Path) -> None:
    root, into, view = view_of(tmp_path)
    spec = make_spec("cfg", config_filenames=(".fakerc", ".fakerc.*"))
    hidden = neutralise_repo_config(view, spec)
    assert hidden == [".fakerc", "src/.fakerc.json"]
    assert not (view / ".fakerc").exists()
    assert not (view / "src" / ".fakerc.json").exists()
    assert (view / "src" / "app.py").is_file()
    kept = into / HIDDEN_DIRECTORY / "cfg"
    assert (kept / ".fakerc").is_file() and (kept / "src" / ".fakerc.json").is_file()
    assert (root / ".fakerc").is_file(), "the original tree is untouched"
    assert not (view / "src" / "app.py").stat().st_mode & 0o200 or sys.platform == "win32"


def test_a_spec_without_config_names_hides_nothing(tmp_path: Path) -> None:
    _, _, view = view_of(tmp_path)
    assert neutralise_repo_config(view, make_spec()) == []
    assert (view / ".fakerc").is_file()


def test_remove_view_deletes_read_only_files(tmp_path: Path) -> None:
    _, into, _ = view_of(tmp_path)
    remove_view(into)
    assert not into.exists()


def run_fake(tmp_path: Path, view: Path, *arguments: str) -> Path:
    out = tmp_path / "out"
    request = SandboxRequest(
        engine_id="fake",
        argv=(sys.executable, str(FAKE_ENGINE), *arguments),
        root=view,
        out_dir=out,
        stdout_path=out / "stdout.txt",
        stderr_path=out / "stderr.txt",
        timeout_seconds=30.0,
        workdir=ROOT_TOKEN,
    )
    assert SubprocessSandbox(isolate_network=False).run(request).exit_code == 0
    return out


@pytest.mark.skipif(running_as_root, reason="root ignores file modes")
def test_an_engine_cannot_write_into_the_view(tmp_path: Path) -> None:
    _, _, view = view_of(tmp_path)
    target = f"{ROOT_TOKEN}/src/app.py"
    out = run_fake(
        tmp_path, view, "write", target.replace(ROOT_TOKEN, str(view)), f"{OUTPUT_TOKEN}/w.json"
    )
    assert json.loads((out / "w.json").read_text(encoding="utf-8")) == {"outcome": "refused"}


def test_an_engine_run_in_the_view_does_not_see_the_hidden_config(tmp_path: Path) -> None:
    root, _, view = view_of(tmp_path)
    neutralise_repo_config(view, make_spec("cfg", config_filenames=(".fakerc",)))
    out = run_fake(tmp_path, view, "config", f"{OUTPUT_TOKEN}/c.json")
    seen = json.loads((out / "c.json").read_text(encoding="utf-8"))
    assert seen["rc_present"] is False
    assert ".fakerc" not in seen["files"]
    assert (root / ".fakerc").is_file()
