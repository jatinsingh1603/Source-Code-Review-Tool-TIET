"""A scan writes no migration messages on stderr, and ``init`` leaves the logging level alone.

Alembic narrates every migration at ``info`` unless its logger is held at ``WARNING`` like the
other third-party loggers (ADR-0005, issue 301); the scans below ask for ``info`` so that the
clamp is what keeps them quiet. A project that ``codekavach init`` has set up must not be at
``info`` without asking for it: the starter file has a ``[logging]`` header with every key
commented out, and that header sets nothing (issue 302).
"""

from pathlib import Path

import pytest

from tests.support.cli_fixtures import Cli


@pytest.fixture
def initialised(cli: Cli, project_dir: Path) -> Path:
    """A project directory that ``codekavach init`` has written its starter file into."""
    (project_dir / ".git").mkdir()
    assert cli(["init"], cwd=project_dir).exit_code == 0
    return project_dir


def test_a_scan_on_a_fresh_project_writes_no_alembic_message(cli: Cli, initialised: Path) -> None:
    result = cli(["scan", ".", "--log-level", "info"], cwd=initialised)
    assert result.exit_code == 0
    assert (initialised / ".codekavach").is_dir()  # the database was created by this run
    assert "alembic" not in result.stderr.lower()


def test_the_next_scan_is_quiet_too(cli: Cli, initialised: Path) -> None:
    assert cli(["scan", ".", "--log-level", "info"], cwd=initialised).exit_code == 0
    again = cli(["scan", ".", "--log-level", "info"], cwd=initialised)
    assert again.exit_code == 0
    assert "alembic" not in again.stderr.lower()


def test_the_third_party_switch_shows_the_messages_again(cli: Cli, initialised: Path) -> None:
    result = cli(
        ["scan", ".", "--log-level", "info"],
        cwd=initialised,
        env={"CODEKAVACH_LOG_THIRD_PARTY": "1"},
    )
    assert result.exit_code == 0
    assert "alembic.runtime.migration" in result.stderr
    assert "third_party_debug_logging_enabled" in result.stderr


def _origin_of(output: str, key: str) -> str:
    line = next(line for line in output.splitlines() if line.startswith(f"{key} = "))
    return line.split("#", 1)[1].strip()


def test_a_scan_in_an_initialised_project_prints_no_info_event(cli: Cli, initialised: Path) -> None:
    result = cli(["scan", "."], cwd=initialised)
    assert result.exit_code == 0
    assert "[info" not in result.stderr


def test_an_initialised_project_keeps_the_default_logging_settings(
    cli: Cli, initialised: Path
) -> None:
    """The starter file has a ``[logging]`` header and sets no key below it (issue 302)."""
    result = cli(["config", "show", "--origin", "--section", "logging"], cwd=initialised)
    assert result.exit_code == 0
    assert _origin_of(result.stdout, "level") == "default"
    assert _origin_of(result.stdout, "format") == "default"


def test_a_logging_key_that_the_project_sets_is_attributed_to_the_project(
    cli: Cli, project_dir: Path
) -> None:
    (project_dir / ".git").mkdir()
    (project_dir / "codekavach.toml").write_text('[logging]\nlevel = "debug"\n', encoding="utf-8")
    result = cli(["config", "show", "--origin", "--section", "logging"], cwd=project_dir)
    assert result.exit_code == 0
    assert _origin_of(result.stdout, "level").startswith("project:")
    assert _origin_of(result.stdout, "format") == "default"
