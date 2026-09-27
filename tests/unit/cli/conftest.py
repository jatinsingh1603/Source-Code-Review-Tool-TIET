"""CLI test isolation: no terminal forced by the environment the tests happen to run in.

Typer decides at import time to force terminal output when ``FORCE_COLOR``, ``PY_COLORS`` or
``GITHUB_ACTIONS`` is set, which CI and some shells do. Tests assert what users get when output
is not a terminal, so the switch is reset here.
"""

from collections.abc import Iterator
from pathlib import Path

import platformdirs
import pytest
import typer.rich_utils

from codekavach.cli.console import reset_consoles


@pytest.fixture(autouse=True)
def plain_terminal(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("FORCE_COLOR", "PY_COLORS", "GITHUB_ACTIONS", "TTY_COMPATIBLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(typer.rich_utils, "FORCE_TERMINAL", None)
    reset_consoles()
    yield
    reset_consoles()


def _listing(folder: Path) -> list[str] | None:
    if not folder.is_dir():
        return None
    return sorted(str(path) for path in folder.rglob("*"))


@pytest.fixture(autouse=True)
def real_home_untouched() -> Iterator[None]:
    """Fail a test that writes into the developer's real CodeKavach configuration folder."""
    folder = platformdirs.user_config_path("codekavach", appauthor=False, roaming=True)
    before = _listing(folder)
    yield
    if before is not None:
        assert _listing(folder) == before, "a CLI test wrote into the real user folder"
