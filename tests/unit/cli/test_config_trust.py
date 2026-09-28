"""``config trust|untrust`` through the real ``run`` and exit-code mapping (E03-27)."""

import json
from pathlib import Path

import pytest
import typer

from codekavach.cli.config import config_app
from codekavach.config.errors import ProjectTrustError
from codekavach.config.loader import load_settings
from codekavach.config.trust import TrustStore, store_path
from tests.support.cli import CliResult, run_cli

RESTRICTED = (
    '[llm.providers.lab]\nkind = "ollama"\nmodel = "m"\n'
    'base_url = "http://127.0.0.1:11434"\n\n[privacy]\nlevel = "L1"\n'
)
COMMAND = typer.main.get_command(config_app)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / "codekavach.toml").write_text(RESTRICTED, encoding="utf-8")
    return root


@pytest.fixture
def home(tmp_path: Path) -> Path:
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


def config(args: list[str], *, home: Path, cwd: Path, **kwargs: object) -> CliResult:
    return run_cli(args, command=COMMAND, home=home, cwd=cwd, **kwargs)  # type: ignore[arg-type]


def env_of(home: Path) -> dict[str, str]:
    return {"CODEKAVACH_HOME": str(home)}


def test_trust_with_yes_then_edit_lapses(project: Path, home: Path) -> None:
    result = config(["trust", "--yes"], home=home, cwd=project)
    assert result.exit_code == 0, result.stderr
    assert "restricted keys:" in result.stderr
    assert "llm.providers.lab.base_url" in result.stderr
    assert "loosened privacy settings:" in result.stderr
    assert "privacy.level" in result.stderr
    assert "127.0.0.1" not in result.stderr + result.stdout
    loaded = load_settings(target=project, env=env_of(home))
    assert loaded.project_trust == "store"
    with (project / "codekavach.toml").open("a", encoding="utf-8") as handle:
        handle.write("# reviewed?\n")
    with pytest.raises(ProjectTrustError) as info:
        load_settings(target=project, env=env_of(home))
    assert "CK-CFG-040" in {issue.code.value for issue in info.value.issues}


def test_confirmation_yes_and_no(project: Path, home: Path) -> None:
    declined = config(["trust"], home=home, cwd=project, input="n\n", tty=True)
    assert declined.exit_code == 130
    assert TrustStore.load(store_path(env_of(home))).entries() == []
    accepted = config(["trust", str(project)], home=home, cwd=home, input="y\n", tty=True)
    assert accepted.exit_code == 0, accepted.stderr
    assert len(TrustStore.load(store_path(env_of(home))).entries()) == 1


def test_no_terminal_without_yes_fails(project: Path, home: Path) -> None:
    result = config(["trust"], home=home, cwd=project)
    assert result.exit_code == 2
    assert "error[confirmation_required]" in result.stderr


def test_list_both_formats_and_untrust(project: Path, home: Path) -> None:
    assert config(["trust", "--yes"], home=home, cwd=project).exit_code == 0
    listed = config(["trust", "--list", "--format", "json"], home=home, cwd=project)
    [entry] = listed.json["projects"]
    assert Path(entry["root"]).resolve() == project.resolve()
    text = config(["trust", "--list"], home=home, cwd=project)
    assert "sha256" in text.stdout
    removed = config(["untrust"], home=home, cwd=project)
    assert removed.exit_code == 0
    assert "no longer trusted" in removed.stdout
    again = config(["untrust"], home=home, cwd=project)
    assert again.exit_code == 0
    assert "was not trusted" in again.stdout
    assert config(["trust", "--list", "--format", "json"], home=home, cwd=project).json == {
        "projects": []
    }


def test_no_configuration_file(tmp_path: Path, home: Path) -> None:
    empty = tmp_path / "empty"
    (empty / ".git").mkdir(parents=True)
    result = config(["trust", "--yes"], home=home, cwd=empty)
    assert result.exit_code == 2
    assert "error[no_project_config]" in result.stderr


def test_corrupt_store_is_an_error(project: Path, home: Path) -> None:
    store_path(env_of(home)).write_bytes(b"{truncated")
    result = config(["trust", "--list"], home=home, cwd=project)
    assert result.exit_code == 2
    assert "error[trust_store_corrupt]" in result.stderr
    assert "CK-CFG-042" in result.stderr


def test_json_list_is_one_document(project: Path, home: Path) -> None:
    config(["trust", "--yes"], home=home, cwd=project)
    listed = config(["trust", "--list", "--format", "json"], home=home, cwd=project)
    assert json.loads(listed.stdout)["projects"][0]["sha256"]
