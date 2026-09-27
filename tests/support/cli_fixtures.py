"""Pytest fixtures of the CLI harness, registered in ``tests/conftest.py``."""

import functools
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.support.cli import CliResult, run_cli

Cli = Callable[..., CliResult]


@pytest.fixture
def isolated_home(tmp_path: Path) -> Path:
    """The temporary home directory that ``cli`` invocations use."""
    home = tmp_path / "home"
    home.mkdir()
    return home


@pytest.fixture
def project_dir(tmp_path: Path) -> Path:
    """An empty directory to use as the working directory."""
    directory = tmp_path / "project"
    directory.mkdir()
    return directory


@pytest.fixture
def cli(isolated_home: Path) -> Cli:
    """``run_cli`` bound to this test's temporary home."""
    return functools.partial(run_cli, home=isolated_home)
