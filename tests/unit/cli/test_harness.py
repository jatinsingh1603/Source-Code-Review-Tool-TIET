import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import typer

from codekavach.cli._version import get_version
from codekavach.cli.app import app
from codekavach.cli.backends import load_backend
from codekavach.core.pipeline.events import InMemoryEventBus, ScanCancelled, WarningRaised
from tests.support.cli import CLI_TEST_WIDTH, CliResult, assert_no_ansi, run_cli, strip_ansi
from tests.support.fakes import StubOrchestrator, fake_backend

Cli = Callable[..., CliResult]
SEEN: dict[str, object] = {}


def seen(key: str) -> object:
    """Read through a call so that mypy does not narrow the value between invocations."""
    return SEEN.get(key)


@pytest.fixture
def probe_command() -> Iterator[None]:
    """A temporary ``probe`` command on the real app."""

    def probe() -> None:
        typer.echo("to stdout")
        typer.echo("to stderr", err=True)
        SEEN["profile"] = os.environ.get("CODEKAVACH_PROFILE")
        SEEN["stdin_tty"] = sys.stdin.isatty()
        SEEN["home"] = Path.home()
        SEEN["stdin"] = sys.stdin.read()

    app.command("probe")(probe)
    try:
        yield
    finally:
        app.registered_commands[:] = [
            command for command in app.registered_commands if command.name != "probe"
        ]
        SEEN.clear()


def test_version(cli: Cli) -> None:
    assert cli(["--version"]) == CliResult(0, f"codekavach {get_version()}\n", "")


def test_help_is_plain_and_fits(cli: Cli) -> None:
    result = cli(["--help"])
    assert result.exit_code == 0
    assert_no_ansi(result.stdout)
    assert max(len(line) for line in result.stdout.splitlines()) <= CLI_TEST_WIDTH


def test_streams_are_separate(cli: Cli, probe_command: None) -> None:
    result = cli(["probe"])
    assert result.exit_code == 0
    assert result.stdout == "to stdout\n"
    assert result.stderr == "to stderr\n"


def test_inherited_codekavach_variables_are_removed(
    cli: Cli, probe_command: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CODEKAVACH_PROFILE", "ci")
    cli(["probe"])
    assert seen("profile") is None
    cli(["probe"], env={"CODEKAVACH_PROFILE": "ci"})
    assert seen("profile") == "ci"
    assert os.environ["CODEKAVACH_PROFILE"] == "ci"


def test_home_is_isolated(cli: Cli, probe_command: None, isolated_home: Path) -> None:
    cli(["probe"])
    home = SEEN["home"]
    assert isinstance(home, Path)
    assert home.resolve() == isolated_home.resolve()
    assert Path.home().resolve() != isolated_home.resolve()


def test_tty_and_input(cli: Cli, probe_command: None) -> None:
    cli(["probe"], tty=True, input="yes\n")
    assert SEEN["stdin_tty"] is True
    assert SEEN["stdin"] == "yes\n"
    assert sys.stdin.isatty() is not True or os.isatty(0)
    cli(["probe"])
    assert SEEN["stdin_tty"] is False


def test_cwd(cli: Cli, probe_command: None, project_dir: Path) -> None:
    before = Path.cwd()
    cli(["probe"], cwd=project_dir)
    assert Path.cwd() == before


def test_standalone_run_cli() -> None:
    assert run_cli(["--version"]).exit_code == 0


@pytest.mark.parametrize("stdout", ['{"a": 1} {"b": 2}', '{"a": 1} trailing', "", "not json"])
def test_json_requires_one_document(stdout: str) -> None:
    with pytest.raises(AssertionError, match="not one JSON document"):
        _ = CliResult(0, stdout, "").json
    assert CliResult(0, '{"a": 1}\n', "").json == {"a": 1}


def test_ansi_helpers() -> None:
    assert strip_ansi("\x1b[1mbold\x1b[0m") == "bold"
    assert_no_ansi("plain")
    with pytest.raises(AssertionError):
        assert_no_ansi("\x1b[1m")


def test_stub_orchestrator() -> None:
    events = [
        WarningRaised(scan_id="scan_x", code="first"),
        ScanCancelled(scan_id="scan_x", stages_completed=1),
    ]
    stub = StubOrchestrator(events=events, outcome="outcome")
    bus = InMemoryEventBus()
    seen: list[str] = []
    bus.subscribe(lambda event: seen.append(event.kind))
    assert stub("loaded", "repo", bus=bus, salt="s") == "outcome"
    assert seen == ["warning", "scan.cancelled"]
    assert stub.calls[0]["target"] == "repo"
    failing = StubOrchestrator(error=RuntimeError("scripted"))
    with pytest.raises(RuntimeError, match="scripted"):
        failing("loaded", "repo")


def test_fake_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = object()
    fake_backend(monkeypatch, "codekavach.ledger.store.Ledger", fake)
    assert load_backend("codekavach.ledger.store", "Ledger", feature="ledger", epic="E12") is fake
