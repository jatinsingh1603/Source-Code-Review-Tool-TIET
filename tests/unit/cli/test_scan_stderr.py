"""A scan writes no migration messages on stderr (issue 301).

``codekavach init`` writes a ``[logging]`` table, so the effective console level of a project
that was set up that way is ``info``, and Alembic narrates every migration at that level unless
its logger is held at ``WARNING`` like the other third-party loggers (ADR-0005).
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
    result = cli(["scan", "."], cwd=initialised)
    assert result.exit_code == 0
    assert (initialised / ".codekavach").is_dir()  # the database was created by this run
    assert "alembic" not in result.stderr.lower()


def test_the_next_scan_is_quiet_too(cli: Cli, initialised: Path) -> None:
    assert cli(["scan", "."], cwd=initialised).exit_code == 0
    again = cli(["scan", "."], cwd=initialised)
    assert again.exit_code == 0
    assert "alembic" not in again.stderr.lower()


def test_the_third_party_switch_shows_the_messages_again(cli: Cli, initialised: Path) -> None:
    result = cli(["scan", "."], cwd=initialised, env={"CODEKAVACH_LOG_THIRD_PARTY": "1"})
    assert result.exit_code == 0
    assert "alembic.runtime.migration" in result.stderr
    assert "third_party_debug_logging_enabled" in result.stderr
