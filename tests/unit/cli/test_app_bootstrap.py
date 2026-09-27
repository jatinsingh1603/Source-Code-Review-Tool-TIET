import importlib.metadata
import subprocess
import sys

import pytest

from codekavach.cli._version import UNKNOWN_VERSION, get_version
from codekavach.cli.app import main
from codekavach.cli.console import get_console, get_err_console, reset_consoles


def test_version_option(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out == f"codekavach {get_version()}\n"
    assert main(["-V"]) == 0
    assert capsys.readouterr().out == f"codekavach {get_version()}\n"


@pytest.mark.parametrize("argv", [["--help"], ["-h"], []])
def test_help(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert "Usage: codekavach" in captured.out
    assert captured.out.count("Usage: codekavach") == 1


def test_unknown_version(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    assert get_version() == UNKNOWN_VERSION == "0.0.0+unknown"


def test_no_color(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert main(["--help"]) == 0
    assert "\x1b" not in capsys.readouterr().out


def test_unknown_option(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-such-option"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "No such option" in captured.err


def test_consoles(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_consoles()
    assert get_console() is get_console()
    assert get_err_console().stderr is True
    assert get_console().stderr is False
    monkeypatch.setenv("CODEKAVACH_NO_COLOR", "1")
    reset_consoles()
    assert get_console().color_system is None
    reset_consoles()


def test_python_dash_m() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "codekavach", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.startswith("codekavach ")


def test_import_has_no_heavy_side_effects() -> None:
    code = (
        "import codekavach.cli.app, sys; "
        "assert 'codekavach.core.pipeline' not in sys.modules; "
        "assert 'keyring' not in sys.modules"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
