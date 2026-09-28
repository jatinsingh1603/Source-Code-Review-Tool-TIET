"""``config path`` and ``config profiles`` through the real ``run`` mapping (E03-36)."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import typer

from codekavach.cli.config import config_app
from codekavach.config.profiles import PROFILE_DESCRIPTIONS
from codekavach.config.trust import TrustStore
from tests.support.cli import CliResult, run_cli

COMMAND = typer.main.get_command(config_app)


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "repo"
    (project / ".git").mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    return project, home


def config(args: list[str], dirs: tuple[Path, Path], **kwargs: Any) -> CliResult:
    project, home = dirs
    return run_cli(args, command=COMMAND, cwd=project, home=home, **kwargs)


def tree(root: Path) -> list[Path]:
    return sorted(root.rglob("*"))


def test_path_both_formats_creates_nothing(dirs: tuple[Path, Path], tmp_path: Path) -> None:
    project, _ = dirs
    (project / "codekavach.toml").write_text("[scan]\njobs = 2\n", encoding="utf-8")
    before = tree(tmp_path)
    text = config(["path"], dirs)
    assert text.exit_code == 0, text.stderr
    assert "project config" in text.stdout
    assert "missing (created on first scan)" in text.stdout
    as_json = config(["path", "--format", "json"], dirs)
    rows = {row["label"]: row for row in json.loads(as_json.stdout)["paths"]}
    assert rows["project config"]["exists"] is True
    assert rows["state directory"]["exists"] is False
    assert tree(tmp_path) == before


def test_path_with_broken_project_file(dirs: tuple[Path, Path]) -> None:
    project, _ = dirs
    (project / "codekavach.toml").write_text("[scan\n", encoding="utf-8")
    result = config(["path"], dirs)
    assert result.exit_code == 0
    assert "found (does not parse)" in result.stdout


def test_path_trust_store_notes(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    config_file = project / "codekavach.toml"
    config_file.write_text("[scan]\njobs = 2\n", encoding="utf-8")
    store = TrustStore(home / "trusted-projects.json")
    store.grant(project / "elsewhere", hashlib.sha256(b"x").hexdigest())
    assert "found (this project: untrusted)" in config(["path"], dirs).stdout
    store.grant(project, hashlib.sha256(config_file.read_bytes()).hexdigest())
    assert "found (this project: trusted)" in config(["path"], dirs).stdout


def test_profiles_both_formats(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    (home / "config.toml").write_text(
        '[profiles.nightly]\nextends = "ci"\ndescription = "Nightly run"\n', encoding="utf-8"
    )
    (project / "codekavach.toml").write_text(
        '[profiles.review.reporting]\nformats = ["html"]\n', encoding="utf-8"
    )
    as_json = config(["profiles", "--format", "json"], dirs)
    assert as_json.exit_code == 0, as_json.stderr
    rows = {row["name"]: row for row in json.loads(as_json.stdout)}
    for name, description in PROFILE_DESCRIPTIONS.items():
        assert rows[name]["kind"] == "built-in"
        assert rows[name]["description"] == description
    assert rows["nightly"]["extends"] == "ci"
    assert rows["nightly"]["defined_in"].endswith("config.toml")
    assert rows["review"]["kind"] == "user-defined"
    assert set(rows["review"]) == {"name", "kind", "defined_in", "extends", "description"}
    text = config(["profiles"], dirs)
    assert "bank-strict" in text.stdout
    assert "nightly" in text.stdout


def test_profiles_with_broken_file(dirs: tuple[Path, Path]) -> None:
    project, _ = dirs
    (project / "codekavach.toml").write_text("[profiles\n", encoding="utf-8")
    result = config(["profiles", "--format", "json"], dirs)
    assert result.exit_code == 0
    assert "does not parse; its profiles are skipped" in result.stderr
    assert len(json.loads(result.stdout)) == len(PROFILE_DESCRIPTIONS)
