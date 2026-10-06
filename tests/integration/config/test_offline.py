"""Loading configuration, and the commands that do not ask for secrets, stay offline (E03-44).

ADR-0006 D9: no network access, no subprocess, no keyring activity. The explicit patches here
cover more than ``pytest-socket`` does (``getaddrinfo``, process creation, ``os.system``), and
keep the check meaningful for a test that is allowed loopback.
"""

import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

import pytest

from codekavach.config import load_settings, toml_source
from tests.support.cli import CliResult, run_cli
from tests.support.config import ConfigSandbox

FORBIDDEN_MODULES = (
    "keyring", "cryptography", "httpx", "requests", "urllib3", "aiohttp", "litellm", "anthropic",
    "openai", "boto3", "google",
)  # fmt: skip
COMMANDS = (
    ["config", "show"],
    ["config", "validate"],
    ["config", "path"],
    ["config", "profiles"],
    ["config", "schema"],
    ["config", "policy", "show"],
    ["config", "init", "--stdout"],
)


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make every network and process primitive raise; return the attempts that were made."""
    attempts: list[str] = []

    def forbidden(name: str) -> Callable[..., NoReturn]:
        def refuse(*args: Any, **kwargs: Any) -> NoReturn:
            attempts.append(name)
            raise AssertionError(f"{name} was called while loading configuration")

        return refuse

    for owner, name in (
        (socket, "socket"),
        (socket, "create_connection"),
        (socket, "getaddrinfo"),
        (subprocess, "Popen"),
        (os, "system"),
    ):
        monkeypatch.setattr(owner, name, forbidden(f"{owner.__name__}.{name}"))
    if hasattr(os, "posix_spawn"):
        monkeypatch.setattr(os, "posix_spawn", forbidden("os.posix_spawn"))
    return attempts


def populated(sandbox: ConfigSandbox) -> None:
    """A sandbox with a user file, a project file and a profile, like a real project."""
    sandbox.write_user('[privacy]\nlevel = "L3"\n')
    sandbox.write_project('[project]\nname = "demo"\n[scan]\njobs = 2\n')
    sandbox.env["CODEKAVACH_PROFILE"] = "ci"


def test_loading_is_offline(config_sandbox: ConfigSandbox, offline: list[str]) -> None:
    populated(config_sandbox)
    loaded = config_sandbox.load()
    assert loaded.settings.scan.jobs == 2
    assert offline == []


@pytest.mark.parametrize("command", COMMANDS, ids=lambda command: " ".join(command[1:]))
def test_commands_are_offline(
    command: list[str], config_sandbox: ConfigSandbox, offline: list[str]
) -> None:
    populated(config_sandbox)
    result: CliResult = run_cli(
        command, cwd=config_sandbox.root, home=config_sandbox.home, env=config_sandbox.env
    )
    assert result.exit_code == 0, result.stderr
    assert offline == []


def test_the_patches_are_live(offline: list[str]) -> None:
    with pytest.raises(AssertionError, match=r"socket\.create_connection"):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(AssertionError, match="getaddrinfo"):
        socket.getaddrinfo("example.invalid", 443)
    with pytest.raises(AssertionError, match="Popen"):
        subprocess.Popen(["true"])  # noqa: S607
    assert {"socket.create_connection", "socket.getaddrinfo", "subprocess.Popen"} <= set(offline)


def test_a_connection_in_the_loader_fails_the_test(
    config_sandbox: ConfigSandbox, offline: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = toml_source.read_toml

    def phoning_home(*args: Any, **kwargs: Any) -> Any:
        socket.create_connection(("telemetry.example.invalid", 443))
        return real(*args, **kwargs)

    # The loader imports the name, so the name in the loader is the one to replace.
    monkeypatch.setattr("codekavach.config.loader.read_toml", phoning_home)
    populated(config_sandbox)
    with pytest.raises(AssertionError, match="create_connection"):
        config_sandbox.load()
    assert "socket.create_connection" in offline


def test_loading_imports_no_network_client_or_keyring(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    forbidden = json.dumps(FORBIDDEN_MODULES)
    program = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "import codekavach.config\n"
        f"codekavach.config.load_settings(target=Path({str(root)!r}))\n"
        f"hits = [m for m in {forbidden} if m in sys.modules]\n"
        "print(json.dumps(hits))\n"
    )
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("CODEKAVACH_")
    }
    environment["CODEKAVACH_HOME"] = str(tmp_path / "home")
    completed = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=True,
        env=environment,
    )
    assert json.loads(completed.stdout.strip().splitlines()[-1]) == []


def test_load_settings_signature_is_unchanged() -> None:
    # The offline tests call the public entry point; keep a cheap guard on its keyword names.
    names = load_settings.__code__.co_varnames[: load_settings.__code__.co_kwonlyargcount]
    assert {"target", "config_file", "profile", "env"} <= set(names)
