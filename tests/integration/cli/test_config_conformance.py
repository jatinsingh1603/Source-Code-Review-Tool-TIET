"""The configuration commands of E03, mounted on the root application, follow E05's conventions.

Exit codes, the global loader options and the JSON envelope (E05-19). What the commands print in
their own formats is owned by E03 and pinned by its tests; these cases keep the two epics aligned.
"""

import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click

from codekavach.cli import config as config_module
from codekavach.cli.app import LazyEntry, LazyGroup, build_cli
from codekavach.cli.exit_codes import ExitCode
from codekavach.config import load_settings
from tests.support.cli import CliResult

Cli = Callable[..., CliResult]
INVALID = '[privacy]\nlevel = "L9"\n'
WARNING_ONLY = '[privacy.provider_tier_levels]\npublic = "L2"\n'  # CK-CFG-038, in the user file
TERMS = '[privacy]\ndomain_terms = ["kavachbank", "accrual"]\n\n[scan]\njobs = 2\n'
KEY_REFERENCE = "env:CK_TEST_PROVIDER_KEY"  # a reference to a variable, not a key
KEYED = (
    '[llm]\ndefault_provider = "primary"\n'
    '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
    f'api_key = "{KEY_REFERENCE}"\n'  # pragma: allowlist secret
)


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def config(cli: Cli, project: Path, *args: str, **kwargs: Any) -> CliResult:
    return cli(["config", *args], cwd=project, **kwargs)


# mounting


def test_root_help_lists_config_and_init(cli: Cli) -> None:
    result = cli(["--help"])
    assert result.exit_code == 0
    commands = set(re.findall(r"^\s*[│|]?\s*([a-z]+)\s{2,}", result.stdout, flags=re.MULTILINE))
    assert {"config", "init", "scan", "report", "privacy"} <= commands
    for name in ("show", "validate", "path", "profiles", "key", "trust", "init"):
        assert name in cli(["config", "--help"]).stdout


def test_init_is_a_top_level_command(cli: Cli, project: Path) -> None:
    result = cli(["init", "--stdout"], cwd=project)
    assert result.exit_code == 0, result.stderr
    assert "[privacy]" in result.stdout
    assert result.stdout == config(cli, project, "init", "--stdout").stdout


def test_optional_commands_skip_what_is_absent() -> None:
    before = set(sys.modules)
    absent = LazyEntry("absent", "codekavach.cli.module_that_does_not_exist:x", "command", "x",
                       optional=True)  # fmt: skip
    assert absent.available() is False
    assert set(sys.modules) == before  # checked without importing anything
    root = build_cli()
    assert isinstance(root, LazyGroup)
    names = root.list_commands(click.Context(root))
    assert "absent" not in names
    assert {"config", "init"} <= set(names)
    broken = LazyEntry("broken", "codekavach.cli.config:no_such_attribute", "command", "x",
                       optional=True)  # fmt: skip
    assert broken.available() is True
    with pytest.raises(click.ClickException, match="command 'broken' is not available"):
        root.resolve_lazy(broken)


def test_config_module_uses_exit_code_members_only() -> None:
    source = Path(config_module.__file__).read_text(encoding="utf-8")
    assert not re.findall(r"(?:typer\.Exit|SystemExit|sys\.exit|exit)\(\s*-?\d", source)
    assert "typer.Exit(ExitCode." in source


# exit codes


def test_validate_exit_codes(cli: Cli, project: Path, isolated_home: Path) -> None:
    assert config(cli, project, "validate").exit_code == ExitCode.OK
    assert config(cli, project, "validate", "--strict").exit_code == ExitCode.OK
    (isolated_home / "config.toml").write_text(WARNING_ONLY, encoding="utf-8")
    assert config(cli, project, "validate").exit_code == ExitCode.OK
    assert config(cli, project, "validate", "--strict").exit_code == ExitCode.FINDINGS
    (project / "codekavach.toml").write_text(INVALID, encoding="utf-8")
    assert config(cli, project, "validate").exit_code == ExitCode.USAGE
    assert config(cli, project, "validate", "--strict").exit_code == ExitCode.USAGE
    machine = config(cli, project, "validate", "--json")
    assert (machine.exit_code, machine.json["exit_code"]) == (ExitCode.USAGE, ExitCode.USAGE)
    assert machine.json["data"]["valid"] is False


# the envelope


@pytest.mark.parametrize(
    "command",
    [
        ("show",),
        ("show", "--section", "privacy"),
        ("show", "--layer", "project"),
        ("validate",),
        ("path",),
        ("profiles",),
        ("key", "status"),
    ],
    ids="-".join,
)
def test_json_envelope_wraps_the_format_json_document(
    cli: Cli, project: Path, command: tuple[str, ...]
) -> None:
    (project / "codekavach.toml").write_text(TERMS, encoding="utf-8")
    raw = config(cli, project, *command, "--format", "json")
    assert raw.exit_code == 0, raw.stderr
    document = json.loads(raw.stdout)
    wrapped = config(cli, project, *command, "--json")
    assert wrapped.exit_code == 0, wrapped.stderr
    envelope = wrapped.json
    assert envelope["data"] == document
    assert (envelope["ok"], envelope["exit_code"]) == (True, 0)
    assert envelope["command"] == " ".join(("config", *command[: 2 if command[0] == "key" else 1]))
    before = cli(["--json", "config", *command], cwd=project)
    assert before.json["data"] == document
    both = config(cli, project, *command, "--json", "--format", "json")
    assert both.json["data"] == document


def test_validate_json_mirrors_the_exit_code(cli: Cli, project: Path, isolated_home: Path) -> None:
    (isolated_home / "config.toml").write_text(WARNING_ONLY, encoding="utf-8")
    strict = config(cli, project, "validate", "--strict", "--json")
    assert (strict.exit_code, strict.json["exit_code"]) == (ExitCode.FINDINGS, ExitCode.FINDINGS)
    assert strict.json["ok"] is False
    assert len(strict.json["data"]["warnings"]) == 1
    assert strict.json["data"]["valid"] is True


@pytest.mark.parametrize(
    "command",
    [("show", "--format", "toml"), ("validate", "--format", "text"), ("path", "--format", "text")],
    ids=lambda command: command[0],
)
def test_json_with_another_format_is_a_usage_error(
    cli: Cli, project: Path, command: tuple[str, ...]
) -> None:
    result = config(cli, project, *command, "--json")
    assert result.exit_code == ExitCode.USAGE
    assert [error["code"] for error in result.json["errors"]] == ["format_conflict"]
    assert config(cli, project, command[0]).exit_code == 0  # the default format is no conflict


# masking


def test_masking_applies_inside_the_envelope(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (project / "codekavach.toml").write_text(TERMS + KEYED, encoding="utf-8")
    trust = "--trust-project-config"
    result = config(cli, project, "show", "--json", trust, env={"CK_TEST_PROVIDER_KEY": "planted"})
    assert result.exit_code == 0, result.stderr
    settings = result.json["data"]["settings"]
    assert "kavachbank" not in result.stdout
    assert "accrual" not in result.stdout
    assert "planted" not in result.stdout
    assert settings["scan"]["jobs"] == 2
    shown_reference = settings["llm"]["providers"]["primary"]["api_key"]
    assert shown_reference == KEY_REFERENCE
    raw = config(cli, project, "show", "--format", "json", trust)
    assert result.json["data"] == json.loads(raw.stdout)


# global loader options


def test_loader_options_before_or_after_the_command_are_identical(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (project / "explicit.toml").write_text("[scan]\njobs = 3\n", encoding="utf-8")
    captured: list[dict[str, Any]] = []
    real = load_settings

    def recording(**kwargs: Any) -> Any:
        captured.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(config_module, "load_settings", recording)
    options = [
        "--config", "explicit.toml", "--profile", "ci", "--no-user-config",
        "--trust-project-config", "--set", "scan.jobs=5",
    ]  # fmt: skip
    after = cli(["config", "show", *options], cwd=project)
    before = cli([*options, "config", "show"], cwd=project)
    assert after.exit_code == before.exit_code == 0, after.stderr + before.stderr
    assert after.stdout == before.stdout
    assert "jobs = 5" in after.stdout
    first, second = captured
    assert first["config_file"] == second["config_file"] == Path("explicit.toml")
    assert (first["profile"], first["use_user_config"], first["trust_project_config"]) == (
        "ci",
        False,
        True,
    )
    assert {key: value for key, value in first.items() if key != "cli_overrides"} == {
        key: value for key, value in second.items() if key != "cli_overrides"
    }
    assert first["cli_overrides"].data == second["cli_overrides"].data == {"scan": {"jobs": 5}}
    validated = cli(["config", "validate", *options], cwd=project)
    assert validated.exit_code == 0, validated.stderr
