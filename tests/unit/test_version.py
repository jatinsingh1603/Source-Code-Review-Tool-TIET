"""The package installs, reports one version and exposes a working entry point."""

import re
from importlib.metadata import version

from typer.testing import CliRunner

import codekavach
from codekavach.cli.app import app

# PEP 440 public version, with optional local segment.
PEP440 = re.compile(
    r"^([1-9][0-9]*!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*"
    r"((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?"
    r"(\+[a-z0-9]+(\.[a-z0-9]+)*)?$"
)

runner = CliRunner()


def test_version_matches_metadata() -> None:
    assert codekavach.__version__ == version("codekavach")


def test_version_is_pep440() -> None:
    assert PEP440.match(codekavach.__version__)


def test_version_option() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout == f"codekavach {codekavach.__version__}\n"


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout == f"codekavach {codekavach.__version__}\n"


def test_no_arguments_prints_help() -> None:
    result = runner.invoke(app, [])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Usage" in result.output
