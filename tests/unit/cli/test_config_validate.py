"""``config validate`` through the real ``run`` and exit-code mapping (E03-35)."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
import typer

from codekavach.cli.config import config_app
from codekavach.cli.options import attach_global_options
from tests.support.cli import CliResult, assert_no_ansi, run_cli

COMMAND = typer.main.get_command(config_app)
attach_global_options(COMMAND)  # the loader options are global options (E05-19)
WARNING_ONLY = '[privacy.provider_tier_levels]\npublic = "L2"\n'  # 038, in the user file


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "repo"
    (project / ".git").mkdir(parents=True)
    home = tmp_path / "home"
    home.mkdir()
    return project, home


def validate(args: list[str], dirs: tuple[Path, Path], **kwargs: Any) -> CliResult:
    project, home = dirs
    return run_cli(["validate", *args], command=COMMAND, cwd=project, home=home, **kwargs)


def test_valid_both_formats(dirs: tuple[Path, Path]) -> None:
    text = validate([], dirs)
    assert text.exit_code == 0, text.stderr
    assert text.stdout == "configuration is valid (profile: none)\n"
    as_json = validate(["--format", "json"], dirs)
    assert as_json.exit_code == 0
    assert_no_ansi(as_json.stdout)
    document = json.loads(as_json.stdout)
    assert set(document) == {"valid", "errors", "warnings", "profile", "project_config"}
    assert document["valid"] is True


def test_invalid_reports_every_issue_of_the_stage(dirs: tuple[Path, Path]) -> None:
    project, _ = dirs
    (project / "codekavach.toml").write_text(
        '[scan]\njobz = 2\nmax_file_size_kb = 0\n\n[privacy]\nlevel = "L1"\nmin_level = "L3"\n',
        encoding="utf-8",
    )
    text = validate(["--trust-project-config"], dirs)
    assert text.exit_code == 2
    assert text.stdout.startswith("configuration is invalid: 3 errors")
    for code in ("CK-CFG-002", "CK-CFG-003", "CK-CFG-037"):
        assert f"error[{code}]" in text.stderr
    as_json = validate(["--trust-project-config", "--format", "json"], dirs)
    assert as_json.exit_code == 2
    document = json.loads(as_json.stdout)
    assert document["valid"] is False
    assert len(document["errors"]) == 3
    assert document["project_config"].endswith("codekavach.toml")


def test_warnings_only_and_strict(dirs: tuple[Path, Path]) -> None:
    _, home = dirs
    (home / "config.toml").write_text(WARNING_ONLY, encoding="utf-8")
    relaxed = validate([], dirs)
    assert relaxed.exit_code == 0
    assert "(profile: none, 1 warning)" in relaxed.stdout
    assert "warning[CK-CFG-038]" in relaxed.stderr
    assert validate(["--strict"], dirs).exit_code == 1
    strict_json = validate(["--strict", "--format", "json"], dirs)
    assert strict_json.exit_code == 1
    assert len(json.loads(strict_json.stdout)["warnings"]) == 1


def test_bad_set_option_is_a_report(dirs: tuple[Path, Path]) -> None:
    result = validate(["--set", "no-equals-sign", "--format", "json"], dirs)
    assert result.exit_code == 2
    assert json.loads(result.stdout)["errors"][0]["code"] == "CK-CFG-061"


def test_check_secrets(memory_keyring: Any, dirs: tuple[Path, Path]) -> None:
    _, home = dirs
    (home / "config.toml").write_text(
        '[llm]\ndefault_provider = "primary"\n\n'
        '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n',
        encoding="utf-8",
    )
    missing = validate(["--check-secrets"], dirs)
    assert missing.exit_code == 2
    assert "error[CK-CFG-012]" in missing.stderr
    value = "value-of-the-anthropic-key"
    present = validate(["--check-secrets"], dirs, env={"ANTHROPIC_API_KEY": value})
    assert present.exit_code == 0, present.stderr
    as_json = validate(
        ["--check-secrets", "--format", "json"], dirs, env={"ANTHROPIC_API_KEY": value}
    )
    for result in (missing, present, as_json):
        assert value not in result.stdout + result.stderr
    assert memory_keyring.store == {}


def test_help_documents_exit_codes_and_pre_commit(dirs: tuple[Path, Path]) -> None:
    result = validate(["--help"], dirs)
    text = " ".join(re.sub(r"[─-╿|]", " ", result.stdout).split())  # unwrap Rich boxes
    assert "1 only with --strict" in text
    assert "codekavach config validate --strict --no-user-config" in text
    assert "reported first and on their own" in text
