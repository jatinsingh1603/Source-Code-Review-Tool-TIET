"""The CLI test harness: run the real command tree in-process, isolated from the real home.

``run_cli`` builds a fresh command with ``codekavach.cli.app.build_cli()`` and calls
``codekavach.cli.app.run`` (the function behind the installed script), so tests see the same
grammar and the same exit-code mapping as users. Typer's and Click's ``CliRunner`` would bypass
both. Each invocation gets a temporary home, a fixed width without colour, separate stdout and
stderr buffers and, optionally, streams that claim to be terminals. A command configures the
process-wide logging (E05-06); the state from before the invocation is restored afterwards.
"""

import contextlib
import io
import json
import logging
import os
import re
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import typer.rich_utils
from typer import _click as click  # the Click copy that Typer's commands use

from codekavach.cli.app import build_cli, run
from codekavach.cli.console import reset_consoles
from codekavach.core.log import config as log_config

CLI_TEST_WIDTH = 100
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_FORCING = ("FORCE_COLOR", "PY_COLORS", "GITHUB_ACTIONS", "TTY_COMPATIBLE")


@dataclass(frozen=True)
class CliResult:
    """What one invocation produced."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def json(self) -> Any:
        """Stdout parsed as exactly one JSON document."""
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError(f"stdout is not one JSON document: {self.stdout!r}") from error


def strip_ansi(text: str) -> str:
    """``text`` without ANSI escape sequences."""
    return _ANSI.sub("", text)


def assert_no_ansi(text: str) -> None:
    """Fail when ``text`` contains an escape character."""
    assert "\x1b" not in text, f"unexpected ANSI escape in {text!r}"


class _Stream(io.StringIO):
    """A text buffer that reports a configurable ``isatty``."""

    def __init__(self, initial: str = "", *, tty: bool = False) -> None:
        super().__init__(initial)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _environment(home: Path, env: Mapping[str, str] | None) -> dict[str, str]:
    base = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("CODEKAVACH_") and key not in _FORCING
    }
    base.update(
        {
            "COLUMNS": str(CLI_TEST_WIDTH),
            "LINES": "40",
            "NO_COLOR": "1",
            "TERM": "dumb",
            "CODEKAVACH_HOME": str(home),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
        }
    )
    base.update(env or {})
    return base


@contextlib.contextmanager
def _patched_environ(values: Mapping[str, str]) -> Iterator[None]:
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


@contextlib.contextmanager
def preserved_logging() -> Iterator[None]:
    """Undo the logging configuration made inside the block and close its log file."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    structlog_config = structlog.get_config()
    stderr_handler, file_handler = log_config._handler, log_config._file_handler
    third_party = {name: logging.getLogger(name).level for name in log_config.THIRD_PARTY_LOGGERS}
    try:
        yield
    finally:
        opened = log_config._file_handler
        if opened is not None and opened is not file_handler:
            opened.close()
        root.handlers[:] = handlers
        root.setLevel(level)
        structlog.configure(**structlog_config)
        log_config._handler, log_config._file_handler = stderr_handler, file_handler
        for name, saved in third_party.items():
            logging.getLogger(name).setLevel(saved)


@contextlib.contextmanager
def _working_directory(path: Path | None) -> Iterator[None]:
    if path is None:
        yield
        return
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def run_cli(
    args: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    input: str | None = None,  # noqa: A002 - mirrors the Click runner's parameter name
    cwd: Path | None = None,
    tty: bool = False,
    home: Path | None = None,
    command: click.Command | None = None,
) -> CliResult:
    """Run ``codekavach <args>`` in-process and capture its outputs and exit code.

    ``command`` runs a sub-application that is not mounted yet (for example ``config_app``
    before E05-19) through the same ``run`` and exit-code mapping.
    """
    home = home or Path(tempfile.mkdtemp(prefix="ck-cli-")) / "home"
    home.mkdir(parents=True, exist_ok=True)
    stdout, stderr = _Stream(tty=tty), _Stream(tty=tty)
    stdin = _Stream(input or "", tty=tty)
    saved_force = typer.rich_utils.FORCE_TERMINAL
    saved_stdin = sys.stdin
    with (
        _patched_environ(_environment(home, env)),
        _working_directory(cwd),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
        preserved_logging(),
    ):
        typer.rich_utils.FORCE_TERMINAL = True if tty else None
        sys.stdin = stdin
        reset_consoles()
        try:
            code = run(command or build_cli(), list(args))
        finally:
            sys.stdin = saved_stdin
            typer.rich_utils.FORCE_TERMINAL = saved_force
            reset_consoles()
    return CliResult(exit_code=code, stdout=stdout.getvalue(), stderr=stderr.getvalue())
