import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import typer

from codekavach.cli.app import app
from codekavach.cli.context import get_context
from codekavach.cli.errors import PrivacyBlockError, UsageError
from codekavach.cli.prompts import confirm, confirm_typed, is_interactive, require_confirmation
from tests.support.cli import CliResult

Cli = Callable[..., CliResult]
SEEN: dict[str, Any] = {}
QUESTION = "Delete the vault?"


@pytest.fixture
def probe() -> Iterator[None]:
    """A temporary ``ask`` command that runs one of the prompt helpers and records the answer."""

    def command(  # noqa: PLR0917 - one switch per behaviour under test
        ctx: typer.Context,
        yes: bool = False,
        default: bool = False,
        typed: str = "",
        load: bool = False,
        require: str = "",
    ) -> None:
        if load:
            _ = get_context(ctx).loaded
        SEEN["interactive"] = is_interactive(ctx)
        SEEN["stdin_before"] = sys.stdin.tell()
        if require:
            refusal = (
                PrivacyBlockError("consent was not given", code="consent_required")
                if require == "privacy"
                else UsageError("not confirmed", code="not_confirmed", hint="re-run with --yes")
            )
            require_confirmation(
                ctx, QUESTION, typed=typed or None, assume_yes=yes, refusal=refusal
            )
            SEEN["answer"] = True
        elif typed:
            SEEN["answer"] = confirm_typed(ctx, QUESTION, expected=typed, assume_yes=yes)
        else:
            SEEN["answer"] = confirm(ctx, QUESTION, assume_yes=yes, default=default)
        SEEN["stdin_after"] = sys.stdin.tell()
        typer.echo("DONE")

    app.command("ask")(command)
    try:
        yield
    finally:
        app.registered_commands[:] = [c for c in app.registered_commands if c.name != "ask"]
        SEEN.clear()


def seen(key: str) -> Any:
    return SEEN[key]


def ask(cli: Cli, *args: str, **kwargs: Any) -> CliResult:
    SEEN.clear()
    return cli(["ask", *args], **kwargs)


# is_interactive


def test_terminal_session_is_interactive(cli: Cli, probe: None) -> None:
    ask(cli, tty=True, input="n\n")
    assert seen("interactive") is True


@pytest.mark.parametrize("flag", ["--no-input", "--json"])
def test_flags_make_a_terminal_non_interactive(cli: Cli, probe: None, flag: str) -> None:
    ask(cli, flag, tty=True, input="y\n")
    assert seen("interactive") is False
    assert seen("answer") is False


def test_not_a_terminal_is_non_interactive(cli: Cli, probe: None) -> None:
    ask(cli, tty=False, input="y\n")
    assert seen("interactive") is False


@pytest.mark.parametrize(
    ("value", "interactive"),
    [("", True), ("0", True), ("false", True), ("FALSE", True), ("true", False), ("1", False)],
)
def test_ci_variable(cli: Cli, probe: None, value: str, interactive: bool) -> None:
    ask(cli, tty=True, input="n\n", env={"CI": value})
    assert seen("interactive") is interactive


def test_ci_profile(cli: Cli, probe: None, tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    ask(cli, "--profile", "ci", tty=True, input="y\n", cwd=tmp_path)
    assert seen("interactive") is False
    ask(cli, "--profile", "demo", tty=True, input="n\n", cwd=tmp_path)
    assert seen("interactive") is True
    ask(cli, "--load", tty=True, input="y\n", cwd=tmp_path, env={"CODEKAVACH_PROFILE": "ci"})
    assert seen("interactive") is False


def test_is_interactive_does_not_load_the_configuration(
    cli: Cli, probe: None, tmp_path: Path
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "codekavach.toml").write_text("this is not valid toml [", encoding="utf-8")
    result = ask(cli, tty=True, input="y\n", cwd=tmp_path)
    assert result.exit_code == 0, result.stderr
    assert seen("answer") is True


# confirm


@pytest.mark.parametrize(
    ("typed", "answer"),
    [("y\n", True), ("YES\n", True), ("n\n", False), ("No\n", False), ("\n", False)],
)
def test_confirm_answers(cli: Cli, probe: None, typed: str, answer: bool) -> None:
    result = ask(cli, tty=True, input=typed)
    assert seen("answer") is answer
    assert f"{QUESTION} [y/N] " in result.stderr
    assert QUESTION not in result.stdout
    assert result.stdout == "DONE\n"


def test_empty_answer_gives_the_default(cli: Cli, probe: None) -> None:
    result = ask(cli, "--default", tty=True, input="\n")
    assert seen("answer") is True
    assert "[Y/n]" in result.stderr


def test_three_invalid_answers_mean_no(cli: Cli, probe: None) -> None:
    result = ask(cli, tty=True, input="maybe\nperhaps\nwhat\ny\n")
    assert seen("answer") is False
    assert result.stderr.count(QUESTION) == 3
    retried = ask(cli, tty=True, input="maybe\ny\n")
    assert seen("answer") is True
    assert retried.stderr.count(QUESTION) == 2


def test_end_of_input_means_no(cli: Cli, probe: None) -> None:
    ask(cli, tty=True, input="")
    assert seen("answer") is False
    ask(cli, "--default", tty=True, input="")
    assert seen("answer") is False


def test_non_interactive_session_refuses_without_reading(cli: Cli, probe: None) -> None:
    done = threading.Event()
    results: list[CliResult] = []

    def run() -> None:
        results.append(ask(cli, tty=False, input="y\n"))
        done.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert done.wait(timeout=1.0), "confirm blocked in a non-interactive session"
    assert seen("answer") is False
    assert seen("stdin_before") == seen("stdin_after") == 0
    assert QUESTION not in results[0].stderr


def test_assume_yes_needs_no_terminal(cli: Cli, probe: None) -> None:
    result = ask(cli, "--yes", tty=False)
    assert seen("interactive") is False
    assert seen("answer") is True
    assert QUESTION not in result.stderr
    ask(cli, "--yes", "--typed", "kavachbank", "--no-input", tty=True)
    assert seen("answer") is True


# confirm_typed


@pytest.mark.parametrize(
    ("typed", "answer"),
    [("kavachbank\n", True), ("Kavachbank\n", False), ("kavachbank \n", False), ("\n", False)],
)
def test_confirm_typed_needs_the_exact_text(
    cli: Cli, probe: None, typed: str, answer: bool
) -> None:
    result = ask(cli, "--typed", "kavachbank", tty=True, input=typed)
    assert seen("answer") is answer
    assert "Type kavachbank to confirm: " in result.stderr
    assert result.stdout == "DONE\n"


def test_confirm_typed_is_no_when_non_interactive(cli: Cli, probe: None) -> None:
    ask(cli, "--typed", "kavachbank", tty=False, input="kavachbank\n")
    assert seen("answer") is False


# require_confirmation


def test_require_confirmation_raises_the_given_error(cli: Cli, probe: None) -> None:
    usage = ask(cli, "--require", "usage", tty=True, input="n\n")
    assert usage.exit_code == 2
    assert "not_confirmed" in usage.stderr
    assert "re-run with --yes" in usage.stderr
    privacy = ask(cli, "--require", "privacy", tty=False)
    assert privacy.exit_code == 3
    assert "consent_required" in privacy.stderr
    assert "DONE" not in privacy.stdout


def test_require_confirmation_passes_when_confirmed(cli: Cli, probe: None) -> None:
    assert ask(cli, "--require", "usage", tty=True, input="y\n").exit_code == 0
    assert ask(cli, "--require", "usage", "--yes", tty=False).exit_code == 0
    typed = ask(cli, "--require", "usage", "--typed", "kavachbank", tty=True, input="kavachbank\n")
    assert typed.exit_code == 0
    wrong = ask(cli, "--require", "usage", "--typed", "kavachbank", tty=True, input="other\n")
    assert wrong.exit_code == 2
