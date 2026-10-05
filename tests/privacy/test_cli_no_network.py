"""I1 at the command layer: local commands open no socket and start no unexpected program.

Each listed command runs with network access refused and recorded and with subprocesses
recorded. A command whose back end is not built yet exits 2 with ``backend_unavailable``, which
is also "no network". A command or option that is not registered yet is skipped by name; once
every E05 command issue has landed, ``EXPECT_ALL_COMMANDS`` is switched to true and the list of
skipped cases has to be empty.
"""

import contextlib
import socket
import ssl
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from codekavach.cli.app import build_cli
from codekavach.cli.onboarding import build_notice
from tests.support.cli import CliResult
from tests.support.fakes import fake_backend
from tests.support.no_network import (
    NetworkAttempts,
    executable_name,
    recorded_subprocesses,
    refuse_network,
)

Cli = Callable[..., CliResult]

# Switched to true by the last E05 command issue to land (completion, plugins, doctor probes).
EXPECT_ALL_COMMANDS = False
PROJECT = "<project>"
HOST = "example.invalid"
OK = 0
PROBLEMS = 1
USAGE = 2

# Programs a command may start, by executable base name. Adding one is a reviewed change.
ALLOWED_SUBPROCESSES: dict[str, frozenset[str]] = {"scan": frozenset({"git"})}


@dataclass(frozen=True)
class Case:
    """One invocation: the command path it needs, its arguments and what it may exit with."""

    name: str
    path: tuple[str, ...]
    args: tuple[str, ...]
    option: str | None = None
    codes: frozenset[int] = frozenset({OK})


CASES = (
    Case("version", (), ("--version",)),
    Case("help", (), ("--help",)),
    Case("completion-bash", ("completion",), ("completion", "bash")),
    Case("doctor", ("doctor",), ("doctor",), codes=frozenset({OK, PROBLEMS})),
    Case(
        "doctor-offline-probe-providers",
        ("doctor",),
        ("doctor", "--offline", "--probe-providers"),
        option="--probe-providers",
        codes=frozenset({OK, PROBLEMS}),
    ),
    Case("providers-list", ("providers", "list"), ("providers", "list")),
    Case(
        "providers-list-check-secrets",
        ("providers", "list"),
        ("providers", "list", "--check-secrets"),
    ),
    Case("providers-test-mock", ("providers", "test"), ("providers", "test", "mock")),
    Case("vault-status", ("vault", "status"), ("vault", "status")),
    Case("plugins-list", ("plugins", "list"), ("plugins", "list")),
    Case("plugins-check", ("plugins", "check"), ("plugins", "check")),
    Case("privacy-notice", ("privacy", "notice"), ("privacy", "notice")),
    Case(
        "privacy-consent-status", ("privacy", "consent", "status"), ("privacy", "consent", "status")
    ),
    Case("privacy-ledger-show", ("privacy", "ledger", "show"), ("privacy", "ledger", "show")),
    Case("privacy-ledger-verify", ("privacy", "ledger", "verify"), ("privacy", "ledger", "verify")),
    Case("config-show", ("config", "show"), ("config", "show")),
    Case("config-validate", ("config", "validate"), ("config", "validate")),
    Case("scan-no-llm", ("scan",), ("scan", PROJECT, "--no-llm")),
    Case("scan-offline", ("scan",), ("scan", PROJECT, "--offline")),
    Case("scan-provider-mock", ("scan",), ("scan", PROJECT, "--provider", "mock")),
    Case("report", ("report",), ("report", PROJECT, "--format", "html")),
)


def find_command(path: Sequence[str]) -> Any | None:
    """The command at ``path`` in the current tree, or ``None``."""
    node: Any = build_cli()
    for name in path:
        node = (getattr(node, "commands", None) or {}).get(name)
        if node is None:
            return None
    return node


def missing_part(case: Case) -> str | None:
    """What ``case`` needs that is not registered yet: a command path or an option."""
    command = find_command(case.path)
    if command is None:
        return f"command '{' '.join(case.path)}'"
    if case.option is not None and not any(
        case.option in parameter.opts for parameter in command.params
    ):
        return f"option '{case.option}' of '{' '.join(case.path)}'"
    return None


@dataclass
class FakeRenderer:
    extension: str = "html"

    def render(self, document: object, destination: Path) -> None:
        destination.write_text(repr(document), encoding="utf-8")


@dataclass
class FakeRegistry:
    def names(self) -> Sequence[str]:
        return ["html"]

    def get(self, name: str) -> FakeRenderer:
        return FakeRenderer()


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    (project_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return project_dir


@contextlib.contextmanager
def observed() -> Iterator[tuple[NetworkAttempts, list[str]]]:
    with refuse_network() as network, recorded_subprocesses() as started:
        yield network, started


def check(case: Case, result: CliResult, network: NetworkAttempts, started: list[str]) -> None:
    assert network.attempts == [], case.name
    allowed = ALLOWED_SUBPROCESSES.get(case.path[0] if case.path else "", frozenset())
    assert [name for name in started if name not in allowed] == [], case.name
    if result.exit_code == USAGE and USAGE not in case.codes:
        assert "error[backend_unavailable]" in result.stderr, result.stderr
    else:
        assert result.exit_code in case.codes, result.stderr


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_command_makes_no_network_attempt(
    case: Case,
    cli: Cli,
    project: Path,
    memory_keyring: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = missing_part(case)
    if missing is not None:
        pytest.skip(f"not registered yet: {missing}")
    if case.name == "report":
        assert cli(["scan", str(project), "--no-llm"], cwd=project).exit_code == OK
        fake_backend(
            monkeypatch,
            "codekavach.report.model.build_report_document",
            lambda scan, findings: (scan.id, len(findings)),
        )
        fake_backend(monkeypatch, "codekavach.report.render.renderer_registry", FakeRegistry)
    args = [str(project) if argument == PROJECT else argument for argument in case.args]
    with observed() as (network, started):
        result = cli(args, cwd=project)
    check(case, result, network, started)
    if case.name == "report":
        assert result.exit_code == OK, result.stderr


def test_the_skip_list_is_empty_once_every_command_has_landed() -> None:
    missing = [part for part in map(missing_part, CASES) if part is not None]
    if EXPECT_ALL_COMMANDS:
        assert missing == []
    else:
        assert missing, "every listed command is registered: set EXPECT_ALL_COMMANDS = True"


def test_case_list_covers_the_documented_commands() -> None:
    assert len(CASES) == 21
    assert len({case.name for case in CASES}) == len(CASES)
    assert set(ALLOWED_SUBPROCESSES) == {"scan"}


# the guard is seen to fail


def test_a_connection_from_a_command_is_caught(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A command that connects, and swallows the refusal, still leaves a recorded attempt."""
    original = build_notice

    def phones_home(*args: Any, **kwargs: Any) -> Any:
        with contextlib.suppress(AssertionError):
            socket.create_connection(("example.invalid", 443))
        return original(*args, **kwargs)

    monkeypatch.setattr("codekavach.cli.privacy.build_notice", phones_home)
    with observed() as (network, started):
        result = cli(["privacy", "notice"], cwd=project)
    assert result.exit_code == OK
    assert network.attempts == ["socket.create_connection(('example.invalid', 443))"]
    with pytest.raises(AssertionError):
        check(CASES[11], result, network, started)


def test_an_unexpected_subprocess_is_caught(cli: Cli, project: Path) -> None:
    with observed() as (network, started):
        subprocess.run([sys.executable, "-c", "pass"], check=True)
        result = cli(["privacy", "notice"], cwd=project)
    assert started == [executable_name(sys.executable)]
    with pytest.raises(AssertionError):
        check(CASES[11], result, network, started)
    scan = next(case for case in CASES if case.name == "scan-no-llm")
    check(scan, result, network, ["git"])
    with pytest.raises(AssertionError):
        check(scan, result, network, ["git", "curl"])


# the helper


def test_helper_records_an_attempt_that_the_caller_swallows() -> None:
    with refuse_network() as network:
        with contextlib.suppress(AssertionError):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with contextlib.suppress(AssertionError):
            socket.getaddrinfo("example.invalid", 443)
        with contextlib.suppress(AssertionError):
            socket.create_connection(("192.0.2.1", 80), timeout=1)
        with contextlib.suppress(AssertionError):
            unconnected: Any = object()
            ssl.create_default_context().wrap_socket(unconnected, server_hostname=HOST)
        with pytest.raises(AssertionError, match=r"network access attempted: socket.getaddrinfo"):
            socket.getaddrinfo("example.invalid", 80)
    assert network.count == 5
    assert network.attempts[1] == "socket.getaddrinfo('example.invalid', 443)"
    assert network.attempts[2] == "socket.create_connection(('192.0.2.1', 80))"
    assert "example.invalid" in network.attempts[3]


def test_helper_restores_what_it_patched() -> None:
    before = (
        socket.socket,
        socket.create_connection,
        socket.getaddrinfo,
        ssl.SSLContext.wrap_socket,
    )
    popen = subprocess.Popen
    with observed():
        assert socket.socket is not before[0]
        assert subprocess.Popen is not popen
    after = (
        socket.socket,
        socket.create_connection,
        socket.getaddrinfo,
        ssl.SSLContext.wrap_socket,
    )
    assert after == before
    assert subprocess.Popen is popen


def test_no_network_fixture(no_network: NetworkAttempts) -> None:
    with pytest.raises(AssertionError, match="network access attempted"):
        socket.create_connection(("example.invalid", 443))
    assert no_network.count == 1


def test_executable_name() -> None:
    assert executable_name(["git", "status"]) == "git"
    assert executable_name([Path("C:/Program Files/Git/cmd/git.EXE"), "log"]) == "git"
    assert executable_name("/usr/bin/git") == "git"
    assert executable_name("git rev-parse HEAD") == "git"
    assert executable_name(b"/usr/bin/curl -s https://example.invalid") == "curl"
