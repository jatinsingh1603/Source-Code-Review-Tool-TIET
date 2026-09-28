"""``config init`` through the real ``run`` and exit-code mapping (E03-37)."""

from pathlib import Path
from typing import Any

import pytest
import typer

from codekavach.cli import config as config_module
from codekavach.cli.config import config_app
from codekavach.config import load_settings
from tests.support.cli import CliResult, run_cli

COMMAND = typer.main.get_command(config_app)


@pytest.fixture
def home(tmp_path: Path) -> Path:
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


def init(args: list[str], cwd: Path, home: Path, **kwargs: Any) -> CliResult:
    return run_cli(["init", *args], command=COMMAND, cwd=cwd, home=home, **kwargs)


def repo(tmp_path: Path, name: str = "payments-api") -> Path:
    root = tmp_path / name
    (root / ".git").mkdir(parents=True)
    return root


def test_writes_validates_refuses_and_forces(tmp_path: Path, home: Path) -> None:
    root = repo(tmp_path)
    first = init([], root, home)
    assert first.exit_code == 0, first.stderr
    target = root / "codekavach.toml"
    assert "Next steps:" in first.stdout
    assert "recommended: add .codekavach/" in first.stdout
    loaded = load_settings(target=root, config_file=target, env={"CODEKAVACH_HOME": str(home)})
    assert loaded.settings.project.name == "payments-api"
    original = target.read_bytes()
    again = init([], root, home)
    assert again.exit_code == 2
    assert "error[config_exists]" in again.stderr
    assert target.read_bytes() == original
    forced = init(["--force", "--profile", "demo"], root, home)
    assert forced.exit_code == 0, forced.stderr
    assert (root / "codekavach.toml.bak").read_bytes() == original
    assert 'profile = "demo"' in target.read_text(encoding="utf-8")


def test_stdout_writes_nothing(tmp_path: Path, home: Path) -> None:
    root = repo(tmp_path)
    before = sorted(root.rglob("*"))
    result = init(["--stdout", "--minimal"], root, home)
    assert result.exit_code == 0
    assert result.stdout.startswith("#:schema ")
    assert sorted(root.rglob("*")) == before


def test_update_gitignore(tmp_path: Path, home: Path) -> None:
    root = repo(tmp_path)
    (root / ".gitignore").write_text("node_modules/", encoding="utf-8")
    result = init(["--update-gitignore"], root, home)
    assert "added to .gitignore: .codekavach/, codekavach-report/" in result.stdout
    assert (root / ".gitignore").read_text(encoding="utf-8") == (
        "node_modules/\n.codekavach/\ncodekavach-report/\n"
    )
    outside = tmp_path / "plain"
    outside.mkdir()
    result = init(["--update-gitignore"], outside, home)
    assert "not a git work tree" in result.stdout
    assert not (outside / ".gitignore").exists()


def test_not_a_directory_and_unknown_profile(tmp_path: Path, home: Path) -> None:
    root = repo(tmp_path)
    file = root / "file.txt"
    file.write_text("x", encoding="utf-8")
    assert init([str(file)], root, home).exit_code == 2
    unknown = init(["--profile", "nope"], root, home)
    assert unknown.exit_code == 2
    assert "error[CK-CFG-020]" in unknown.stderr
    assert not (root / "codekavach.toml").exists()


def test_user_defined_profile_is_accepted(tmp_path: Path, home: Path) -> None:
    root = repo(tmp_path)
    (home / "config.toml").write_text('[profiles.team]\nextends = "ci"\n', encoding="utf-8")
    result = init(["--profile", "team"], root, home)
    assert result.exit_code == 0, result.stderr


def test_broken_template_leaves_no_file(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repo(tmp_path)
    monkeypatch.setattr(config_module, "render_starter", lambda **_: "[scan]\njobs = -5\n")
    result = init([], root, home)
    assert result.exit_code == 4
    assert sorted(p.name for p in root.iterdir()) == [".git"]
