"""Loading configuration, and the commands that do not ask for secrets, stay offline (E03-44).

ADR-0006 D9: no network access, no subprocess, no keyring activity. The explicit patches here
cover more than ``pytest-socket`` does (``getaddrinfo``, process creation, ``os.system``), and
keep the check meaningful for a test that is allowed loopback.

The patches are a context manager used inside the test body, not a fixture. pytest-socket
restores the real socket in its own teardown hook, which runs before fixture finalisers; a
fixture that patched ``socket.socket`` would put the guarded class back afterwards and leave the
next test, one that is allowed loopback, with sockets blocked.
"""

import contextlib
import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable, Iterator
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


@contextlib.contextmanager
def offline() -> Iterator[list[str]]:
    """Make every network and process primitive raise; yield the attempts that were made."""
    attempts: list[str] = []

    def forbidden(name: str) -> Callable[..., NoReturn]:
        def refuse(*args: Any, **kwargs: Any) -> NoReturn:
            attempts.append(name)
            raise AssertionError(f"{name} was called while loading configuration")

        return refuse

    with pytest.MonkeyPatch.context() as patch:
        for owner, name in (
            (socket, "socket"),
            (socket, "create_connection"),
            (socket, "getaddrinfo"),
            (subprocess, "Popen"),
            (os, "system"),
        ):
            patch.setattr(owner, name, forbidden(f"{owner.__name__}.{name}"))
        if hasattr(os, "posix_spawn"):
            patch.setattr(os, "posix_spawn", forbidden("os.posix_spawn"))
        yield attempts


def populated(sandbox: ConfigSandbox) -> None:
    """A sandbox with a user file, a project file and a profile, like a real project."""
    sandbox.write_user('[privacy]\nlevel = "L3"\n')
    sandbox.write_project('[project]\nname = "demo"\n[scan]\njobs = 2\n')
    sandbox.env["CODEKAVACH_PROFILE"] = "ci"


def test_loading_is_offline(config_sandbox: ConfigSandbox) -> None:
    populated(config_sandbox)
    with offline() as attempts:
        loaded = config_sandbox.load()
    assert loaded.settings.scan.jobs == 2
    assert attempts == []


@pytest.mark.parametrize("command", COMMANDS, ids=lambda command: " ".join(command[1:]))
def test_commands_are_offline(command: list[str], config_sandbox: ConfigSandbox) -> None:
    populated(config_sandbox)
    with offline() as attempts:
        result: CliResult = run_cli(
            command, cwd=config_sandbox.root, home=config_sandbox.home, env=config_sandbox.env
        )
    assert result.exit_code == 0, result.stderr
    assert attempts == []


def test_the_patches_are_live() -> None:
    with offline() as attempts:
        with pytest.raises(AssertionError, match=r"socket\.create_connection"):
            socket.create_connection(("127.0.0.1", 9))
        with pytest.raises(AssertionError, match="getaddrinfo"):
            socket.getaddrinfo("example.invalid", 443)
        with pytest.raises(AssertionError, match="Popen"):
            subprocess.Popen(["true"])  # noqa: S607
        with pytest.raises(AssertionError, match=r"socket\.socket"):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    assert {
        "socket.create_connection",
        "socket.getaddrinfo",
        "subprocess.Popen",
        "socket.socket",
    } <= set(attempts)


def primitives() -> tuple[object, ...]:
    return (
        socket.socket,
        socket.create_connection,
        socket.getaddrinfo,
        subprocess.Popen,
        os.system,
        getattr(os, "posix_spawn", None),
    )


def test_the_patches_are_undone_before_the_test_ends() -> None:
    # Whatever this module leaves patched reaches the next test, because pytest-socket's teardown
    # runs before fixture finalisers. Leaving the context must restore every primitive.
    before = primitives()
    with offline():
        assert primitives() != before
    assert primitives() == before


def test_a_connection_in_the_loader_fails_the_test(
    config_sandbox: ConfigSandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = toml_source.read_toml

    def phoning_home(*args: Any, **kwargs: Any) -> Any:
        socket.create_connection(("telemetry.example.invalid", 443))
        return real(*args, **kwargs)

    # The loader imports the name, so the name in the loader is the one to replace.
    monkeypatch.setattr("codekavach.config.loader.read_toml", phoning_home)
    populated(config_sandbox)
    with offline() as attempts, pytest.raises(AssertionError, match="create_connection"):
        config_sandbox.load()
    assert "socket.create_connection" in attempts


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


def test_the_patches_do_not_reach_the_next_test() -> None:
    # The leak that this module once had only showed in a later test that is allowed loopback, in
    # one particular order. Run exactly that order in a child pytest and expect it to pass.
    root = Path(__file__).resolve().parents[3]
    here = f"{Path(__file__).relative_to(root).as_posix()}::test_the_patches_are_live"
    later = (
        "tests/privacy/test_network_blocked.py::test_declared_loopback_is_allowed_and_nothing_else"
    )
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", here, later, "-p", "no:randomly", "-q", "--color=no"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "2 passed" in completed.stdout
