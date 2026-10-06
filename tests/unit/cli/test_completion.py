"""Shell completion (E05-28)."""

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from codekavach.cli import completion
from codekavach.cli.app import build_cli
from tests.support.cli import CliResult, run_cli

SHELLS = ("bash", "zsh", "fish", "powershell")


def complete(words: str, *, cwd: Path | None = None, home: Path | None = None) -> list[str]:
    """Candidates for the last word of ``words`` through the bash environment protocol."""
    parts = words.split(" ")
    env = {
        "_CODEKAVACH_COMPLETE": "bash_complete",
        "COMP_WORDS": words,
        "COMP_CWORD": str(len(parts) - 1),
    }
    result = run_cli([], env=env, cwd=cwd, home=home)
    assert result.exit_code == 0, result.stderr
    assert result.stderr == ""
    return result.stdout.split()


@pytest.mark.parametrize("shell", SHELLS)
def test_script_for_every_shell(shell: str) -> None:
    result = run_cli(["completion", shell])
    assert result.exit_code == 0, result.stderr
    assert "_CODEKAVACH_COMPLETE" in result.stdout
    assert result.stderr == ""  # not a terminal: no install hints


def test_install_hint_on_a_terminal() -> None:
    result = run_cli(["completion", "fish"], tty=True)
    assert result.exit_code == 0
    assert "~/.config/fish/completions/codekavach.fish" in result.stderr


def test_json_is_ignored() -> None:
    result = run_cli(["completion", "bash", "--json"])
    assert result.exit_code == 0
    assert result.stdout.lstrip().startswith("_codekavach_completion()")
    assert '"schema_version"' not in result.stdout


@pytest.mark.parametrize(
    ("shell_var", "expected"),
    [("/bin/bash", "bash"), ("/usr/bin/zsh", "zsh"), ("/usr/local/bin/fish", "fish"),
     ("C:/Program Files/PowerShell/7/pwsh.exe", "powershell")],
)  # fmt: skip
def test_shell_detection(shell_var: str, expected: str) -> None:
    assert completion.detect_shell({"SHELL": shell_var}) == expected
    result = run_cli(["completion"], env={"SHELL": shell_var})
    assert result.exit_code == 0, result.stderr


def test_unknown_shell_is_a_usage_error() -> None:
    assert completion.detect_shell({"SHELL": "/bin/tcsh"}) is None
    result = run_cli(["completion"], env={"SHELL": "/bin/tcsh", "PSModulePath": ""})
    assert result.exit_code == 2
    assert "shell_unknown" in result.stderr
    assert run_cli(["completion", "cmd"]).exit_code == 2


@pytest.mark.parametrize(
    ("instruction", "expected"),
    [("bash_complete", ("complete", "bash")), ("complete_bash", ("complete", "bash")),
     ("zsh_source", ("source", "zsh")), ("source_pwsh", ("source", "powershell")),
     ("bash", None), ("explode_bash", None), ("complete_tcsh", None)],
)  # fmt: skip
def test_instruction_parsing(instruction: str, expected: tuple[str, str] | None) -> None:
    assert completion.parse_instruction(instruction) == expected


def test_command_names() -> None:
    assert "scan" in complete("codekavach sc")
    assert "completion" in complete("codekavach comp")


def test_option_values() -> None:
    assert complete("codekavach scan --fail-on ") == [
        "critical", "high", "medium", "low", "info", "none",
    ]  # fmt: skip
    assert complete("codekavach scan --privacy-level L") == ["L0", "L1", "L2", "L3", "L4"]
    assert "sarif" in complete("codekavach scan --format ")
    assert {"demo", "ci"} <= set(complete("codekavach scan --profile "))
    assert "mock" in complete("codekavach scan --provider ")
    assert "runtime" in complete("codekavach doctor --category ")
    assert "mock" in complete("codekavach providers test ")


def test_global_options_after_a_subcommand() -> None:
    assert {"--privacy-level", "--profile", "--progress"} <= set(complete("codekavach scan --pr"))


def test_malformed_project_config_falls_back(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "codekavach.toml").write_text("this is [ not toml\n", encoding="utf-8")
    profiles = complete("codekavach scan --profile ", cwd=project)
    assert {"airgapped", "bank-strict", "ci", "demo"} <= set(profiles)
    assert complete("codekavach sc", cwd=project) == ["scan"]


def test_configured_profiles_are_offered(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "codekavach.toml").write_text(
        '[profiles.nightly]\ndescription = "x"\n[profiles.nightly.scan]\njobs = 2\n',
        encoding="utf-8",
    )
    assert "nightly" in complete("codekavach scan --profile ", cwd=project)


def test_command_completion_does_not_load_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(**_: object) -> None:
        raise AssertionError("settings loaded for command-name completion")

    monkeypatch.setattr("codekavach.config.load_settings", explode)
    assert complete("codekavach sc") == ["scan"]
    assert {"--privacy-level", "--profile"} <= set(complete("codekavach scan --pr"))


def test_value_callbacks_respect_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(completion, "_load_settings", lambda: time.sleep(2))
    started = time.perf_counter()
    names = completion.complete_profile(None, [], "")  # type: ignore[arg-type]
    elapsed = time.perf_counter() - started
    assert {"demo", "ci"} <= set(names)
    assert elapsed < completion.CONFIG_BUDGET_SECONDS + 0.5


def test_value_callbacks_swallow_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    from codekavach.config.errors import ConfigError, ConfigErrorCode  # noqa: PLC0415

    def broken() -> None:
        raise ConfigError.single(ConfigErrorCode.CK_CFG_005, "unreadable")

    monkeypatch.setattr(completion, "_load_settings", broken)
    assert completion.complete_provider(None, [], "") == ["mock"]  # type: ignore[arg-type]


def test_no_file_is_written_under_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    complete("codekavach sc", home=home)
    complete("codekavach scan --profile ", home=home)
    run_cli(["completion", "bash"], home=home)
    assert sorted(home.rglob("*")) == []


def test_powershell_completion_class_exists() -> None:
    from typer._click.shell_completion import get_completion_class  # noqa: PLC0415
    from typer._completion_classes import completion_init  # noqa: PLC0415

    completion_init()
    for shell in SHELLS:
        assert get_completion_class(shell) is not None, shell
    assert "_CODEKAVACH_COMPLETE" in completion.completion_script("powershell", build_cli())


def _script(shell: str) -> CliResult:
    result = run_cli(["completion", shell])
    assert result.exit_code == 0
    return result


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_script_syntax(shell: str, tmp_path: Path) -> None:
    program = shutil.which(shell)
    if program is None:
        pytest.skip(f"{shell} is not installed")
    script = tmp_path / f"completion.{shell}"
    script.write_text(_script(shell).stdout, encoding="utf-8", newline="\n")
    checked = subprocess.run(
        [program, "-n", str(script)], capture_output=True, text=True, check=False
    )
    assert checked.returncode == 0, checked.stderr
