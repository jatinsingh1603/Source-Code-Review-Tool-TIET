"""``config key set|delete|status`` through the real ``run`` and exit-code mapping (E03-33)."""

import getpass
import json
import logging
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest
import typer

from codekavach.cli.config import check_key_name, config_app
from codekavach.cli.errors import UsageError
from tests.support.cli import CliResult, run_cli
from tests.support.synthetic import example_secret

COMMAND = typer.main.get_command(config_app)
STATES = {"set", "not-set", "backend-unavailable", "error"}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    return root


def key(args: list[str], *, cwd: Path, **kwargs: Any) -> CliResult:
    return run_cli(["key", *args], command=COMMAND, cwd=cwd, **kwargs)


def test_set_overwrite_and_reference(memory_keyring: Any, project: Path) -> None:
    value = example_secret("anthropic_api_key")
    result = key(["set", "primary", "--stdin"], cwd=project, input=value + "\n")
    assert result.exit_code == 0, result.stderr
    # pragma: allowlist nextline secret
    assert 'Stored. Reference it as: api_key = "keyring:codekavach/primary"' in result.stdout
    assert memory_keyring.store[("codekavach", "primary")] == value
    assert value not in result.stdout + result.stderr
    again = key(["set", "primary", "--stdin"], cwd=project, input="second-value\r\n")
    assert again.exit_code == 0
    assert memory_keyring.store[("codekavach", "primary")] == "second-value"


def test_prompt_path(memory_keyring: Any, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A captured stream is not a real terminal, so getpass would warn and echo; stand in for it.
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": sys.stdin.readline().rstrip("\n"))
    result = key(["set", "lab"], cwd=project, input="hidden-value\nhidden-value\n", tty=True)
    assert result.exit_code == 0, result.stderr
    assert memory_keyring.store[("codekavach", "lab")] == "hidden-value"
    assert "hidden-value" not in result.stdout + result.stderr


def test_no_positional_value(memory_keyring: Any, project: Path) -> None:
    result = key(["set", "primary", "EXTRA_ARGUMENT"], cwd=project, input="x")
    assert result.exit_code == 2
    assert memory_keyring.store == {}


def test_empty_value_refused(memory_keyring: Any, project: Path) -> None:
    result = key(["set", "primary", "--stdin"], cwd=project, input="\n")
    assert result.exit_code == 2
    assert "error[empty_key]" in result.stderr


def test_closed_stdin_without_flag_fails_fast(memory_keyring: Any, project: Path) -> None:
    started = time.monotonic()
    result = key(["set", "primary"], cwd=project)
    assert time.monotonic() - started < 1.0
    assert result.exit_code == 2
    assert "error[prompt_unavailable]" in result.stderr


def test_delete_and_delete_missing(memory_keyring: Any, project: Path) -> None:
    memory_keyring.set_password("codekavach", "primary", "v")
    refused = key(["delete", "primary"], cwd=project)
    assert refused.exit_code == 2
    assert "error[confirmation_required]" in refused.stderr
    assert key(["delete", "primary", "--yes"], cwd=project).exit_code == 0
    assert memory_keyring.store == {}
    missing = key(["delete", "primary", "--yes"], cwd=project)
    assert missing.exit_code == 0
    assert "nothing to delete" in missing.stdout


def test_delete_with_confirmation(memory_keyring: Any, project: Path) -> None:
    memory_keyring.set_password("codekavach", "primary", "v")
    assert key(["delete", "primary"], cwd=project, input="n\n", tty=True).exit_code == 130
    assert key(["delete", "primary"], cwd=project, input="y\n", tty=True).exit_code == 0
    assert memory_keyring.store == {}


def test_status_both_formats(memory_keyring: Any, project: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / "config.toml").write_text(
        '[llm.providers.primary]\nkind = "anthropic"\nmodel = "m"\n'
        # pragma: allowlist nextline secret
        'api_key = "keyring:codekavach/primary"\n\n'
        '[llm.providers.lab]\nkind = "ollama"\nmodel = "m"\n\n'
        '[integrations.github]\nenabled = true\nrepository = "o/r"\n',
        encoding="utf-8",
    )
    secret = example_secret("github_token")
    memory_keyring.set_password("codekavach", "primary", "stored")
    env = {"GITHUB_TOKEN": secret}
    as_json = key(["status", "--format", "json"], cwd=project, home=home, env=env)
    assert as_json.exit_code == 0, as_json.stderr
    entries = json.loads(as_json.stdout)["entries"]
    assert {entry["state"] for entry in entries if entry["state"] != "-"} <= STATES
    by_ref = {entry["ref"]: entry for entry in entries}
    assert by_ref["keyring:codekavach/primary"]["state"] == "set"
    assert by_ref["env:GITHUB_TOKEN"]["state"] == "set"
    assert by_ref[""]["name"] == "lab"
    text = key(["status"], cwd=project, home=home, env=env)
    assert "(no key required)" in text.stdout
    for output in (as_json, text):
        assert secret not in output.stdout + output.stderr
        assert "stored" not in output.stdout


def test_insecure_backend_refused(project: Path) -> None:
    keyring = pytest.importorskip("keyring")
    backend_module = pytest.importorskip("keyring.backend")
    fake = types.ModuleType("keyrings.alt.file")

    class PlaintextKeyring(backend_module.KeyringBackend):  # type: ignore[misc,name-defined]
        priority = 1

        def get_password(self, service: str, username: str) -> None:
            return None

        def set_password(self, service: str, username: str, password: str) -> None:
            raise AssertionError("must not store")

        def delete_password(self, service: str, username: str) -> None:
            raise AssertionError("must not delete")

    PlaintextKeyring.__module__ = fake.__name__
    previous = keyring.get_keyring()
    keyring.set_keyring(PlaintextKeyring())
    try:
        result = key(["set", "primary", "--stdin"], cwd=project, input="v")
    finally:
        keyring.set_keyring(previous)
    assert result.exit_code == 2
    assert "error[keyring_insecure]" in result.stderr
    assert "CK-CFG-014" in result.stderr


def test_backend_unavailable(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = pytest.importorskip("keyring")

    def broken() -> Any:
        raise RuntimeError("no backend")

    monkeypatch.setattr(keyring, "get_keyring", broken)
    result = key(["set", "primary", "--stdin"], cwd=project, input="v")
    assert result.exit_code == 2
    assert "error[keyring_unavailable]" in result.stderr
    assert "use an env: or file: reference" in result.stderr


def test_no_secret_in_logs(
    memory_keyring: Any, project: Path, caplog: pytest.LogCaptureFixture
) -> None:
    value = example_secret("openai_project_key")
    with caplog.at_level(logging.DEBUG):
        key(["set", "primary", "--stdin"], cwd=project, input=value)
    assert value not in caplog.text


@pytest.mark.parametrize("name", ["primary", "github", "a", "lab_2", "a" * 32])
def test_valid_names(name: str) -> None:
    assert check_key_name(name) == name


@pytest.mark.parametrize("name", ["", "Primary", "2lab", "lab-x", "a" * 33, "a/b"])
def test_invalid_names(name: str) -> None:
    with pytest.raises(UsageError):
        check_key_name(name)
