"""``config show`` through the real ``run`` and exit-code mapping (E03-34)."""

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import typer

from codekavach.cli.config import config_app
from codekavach.config import Settings, load_settings
from tests.support.cli import CliResult, assert_no_ansi, run_cli
from tests.support.golden import assert_matches_golden

COMMAND = typer.main.get_command(config_app)
GOLDEN = Path(__file__).resolve().parents[2] / "golden" / "config"
USER = '[privacy]\nlevel = "L4"\n\n[profiles.team.reporting]\nclassification = "Internal"\n'
PROJECT = (
    'profile = "team"\n\n[privacy]\ndomain_terms = ["kavachbank", "accrual"]\n\n[scan]\njobs = 2\n'
)


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "repo"
    (project / ".git").mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    return project, home


def show(args: list[str], project: Path, home: Path, **kwargs: Any) -> CliResult:
    return run_cli(["show", *args], command=COMMAND, cwd=project, home=home, **kwargs)


def normalise(text: str, project: Path, home: Path) -> str:
    for path, name in ((project, "/repo"), (home, "/home/u")):
        for spelling in {str(path), str(path.resolve())}:
            text = text.replace(spelling, name)
    return text.replace("\\", "/")


def normalise_json(value: Any, project: Path, home: Path) -> Any:
    if isinstance(value, str):
        return normalise(value, project, home)
    if isinstance(value, list):
        return [normalise_json(item, project, home) for item in value]
    if isinstance(value, dict):
        return {key: normalise_json(item, project, home) for key, item in value.items()}
    return value


def write_fixture(project: Path, home: Path) -> None:
    (home / "config.toml").write_text(USER, encoding="utf-8")
    (project / "codekavach.toml").write_text(PROJECT, encoding="utf-8")


# goldens


def test_golden_effective(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    write_fixture(project, home)
    result = show(["--effective"], project, home)
    assert result.exit_code == 0, result.stderr
    assert_matches_golden(normalise(result.stdout, project, home), GOLDEN / "show_effective.toml")


def test_golden_origin(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    write_fixture(project, home)
    result = show(["--origin"], project, home)
    assert result.exit_code == 0, result.stderr
    text = normalise(result.stdout, project, home)
    assert_matches_golden(text, GOLDEN / "show_effective_origin.toml")


def test_golden_json(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    write_fixture(project, home)
    result = show(["--format", "json"], project, home)
    assert result.exit_code == 0, result.stderr
    document = json.loads(result.stdout)
    for key in ("settings", "origins", "profile", "locked_keys", "org_policies"):
        assert key in document
    assert {"project_trust", "warnings"} <= set(document)
    text = json.dumps(normalise_json(document, project, home), indent=2) + "\n"
    assert_matches_golden(text, GOLDEN / "show_effective.json")


# behaviour


def test_empty_directory_round_trip(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    result = show([], project, home)
    assert result.exit_code == 0, result.stderr
    assert_no_ansi(result.stdout)
    (project / "codekavach.toml").write_text(result.stdout, encoding="utf-8")
    reloaded = load_settings(
        target=project, env={"CODEKAVACH_HOME": str(home)}, trust_project_config=True
    )
    assert reloaded.settings == Settings()
    tomllib.loads(result.stdout)


def test_domain_terms_masked_and_revealed(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    write_fixture(project, home)
    for fmt in ("toml", "json"):
        hidden = show(["--format", fmt], project, home)
        assert "kavachbank" not in hidden.stdout + hidden.stderr
        assert "accrual" not in hidden.stdout
        shown = show(["--format", fmt, "--reveal-domain-terms"], project, home)
        assert "kavachbank" in shown.stdout
        assert "accrual" in shown.stdout
        assert "contains client vocabulary" in shown.stderr


def test_layer_project_and_section(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    write_fixture(project, home)
    layer = show(["--layer", "project"], project, home)
    assert layer.exit_code == 0, layer.stderr
    assert tomllib.loads(layer.stdout)["scan"] == {"jobs": 2}
    assert "kavachbank" not in layer.stdout
    llm = show(["--section", "llm"], project, home)
    assert list(tomllib.loads(llm.stdout)) == ["llm"]
    unknown = show(["--section", "nope"], project, home)
    assert unknown.exit_code == 2
    assert "error[unknown_section]" in unknown.stderr
    assert show(["--layer", "bogus"], project, home).exit_code == 2


def test_check_secrets(memory_keyring: Any, dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    (home / "config.toml").write_text(
        '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
        # pragma: allowlist nextline secret
        'api_key = "keyring:codekavach/primary"\n',
        encoding="utf-8",
    )
    memory_keyring.set_password("codekavach", "primary", "the-stored-value")
    as_toml = show(["--check-secrets"], project, home)
    assert "# provider primary keyring:codekavach/primary: set" in as_toml.stdout
    as_json = show(["--check-secrets", "--format", "json"], project, home)
    rows = {row["name"]: row for row in json.loads(as_json.stdout)["secrets"]}
    assert rows["primary"]["state"] == "set"
    assert rows["mock"]["ref"] == ""  # the built-in mock provider needs no key
    for result in (as_toml, as_json):
        assert "the-stored-value" not in result.stdout + result.stderr


def test_invalid_project_file(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    (project / "codekavach.toml").write_text('[scan]\njobs = "many"\n', encoding="utf-8")
    result = show([], project, home)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.startswith("error[CK-CFG-003]")
    assert "1 problem (1 error, 0 warnings)" in result.stderr


def test_keyring_not_imported_without_check_secrets(dirs: tuple[Path, Path]) -> None:
    project, home = dirs
    code = (
        "import sys, typer\n"
        "from codekavach.cli.app import run\n"
        "from codekavach.cli.config import config_app\n"
        "code = run(typer.main.get_command(config_app), ['show'])\n"
        "assert code == 0, code\n"
        "assert 'keyring' not in sys.modules, 'keyring imported'\n"
    )
    env = {**os.environ, "CODEKAVACH_HOME": str(home)}
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
