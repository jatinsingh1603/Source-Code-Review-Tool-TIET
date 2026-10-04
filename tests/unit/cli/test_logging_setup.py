import json
import logging
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import structlog
import typer

from codekavach.cli import logging_setup
from codekavach.cli.app import app
from codekavach.cli.config import config_app
from codekavach.cli.context import CliContext, get_context
from codekavach.cli.logging_setup import configure_cli_logging, log_level_and_format
from codekavach.cli.options import attach_global_options
from codekavach.core.log import config as log_config
from codekavach.core.log import get_logger
from tests.support.cli import CliResult, preserved_logging

Cli = Callable[..., CliResult]
AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _logging_restored() -> Iterator[None]:
    with preserved_logging():
        yield


@pytest.fixture
def probe() -> Iterator[None]:
    """A temporary ``probe`` command that logs at every level, also as a third-party logger."""

    def command(ctx: typer.Context, load: bool = False) -> None:
        context = get_context(ctx)
        if load:
            _ = context.loaded
        log = get_logger("codekavach.probe")
        log.debug("probe_debug")
        log.info("probe_info")
        log.warning("probe_warning", key=AWS_EXAMPLE_KEY)
        log.error("probe_error")
        logging.getLogger("urllib3").debug("third_party_debug")
        typer.echo("RESULT")

    app.command("probe")(command)
    try:
        yield
    finally:
        app.registered_commands[:] = [c for c in app.registered_commands if c.name != "probe"]


def events(result: CliResult) -> set[str]:
    names = ("probe_debug", "probe_info", "probe_warning", "probe_error", "third_party_debug")
    return {name for name in names if name in result.stderr}


@pytest.mark.parametrize(
    ("verbosity", "quiet", "json_mode", "expected"),
    [
        (0, True, False, (logging.ERROR, "console")),
        (0, False, False, (logging.WARNING, "console")),
        (1, False, False, (logging.INFO, "console")),
        (2, False, False, (logging.DEBUG, "console")),
        (3, False, False, (logging.DEBUG, "console")),
        (0, False, True, (logging.WARNING, "json")),
        (1, False, True, (logging.INFO, "json")),
        (0, True, True, (logging.ERROR, "json")),
    ],
)
def test_log_level_and_format(
    verbosity: int, quiet: bool, json_mode: bool, expected: tuple[int, str]
) -> None:
    found = log_level_and_format(verbosity=verbosity, quiet=quiet, json_mode=json_mode)
    assert found == expected


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        (CliContext(), {"level": logging.WARNING, "fmt": "console", "third_party": None}),
        (CliContext(verbosity=1), {"level": logging.INFO, "fmt": "console"}),
        (CliContext(debug=True), {"level": logging.DEBUG, "fmt": "console"}),
        (CliContext(verbosity=3), {"level": logging.DEBUG, "third_party": True}),
        (CliContext(quiet=True, json_mode=True), {"level": logging.ERROR, "fmt": "json"}),
        (CliContext(verbosity=1, log_level="error"), {"level": logging.ERROR}),
        (CliContext(quiet=True, log_level="debug"), {"level": logging.DEBUG}),
        (CliContext(json_mode=True, log_format="console"), {"fmt": "console"}),
        (CliContext(log_file=Path("out.log")), {"log_file": Path("out.log")}),
    ],
)
def test_configure_cli_logging_passes_the_mapped_values(
    monkeypatch: pytest.MonkeyPatch, context: CliContext, expected: dict[str, Any]
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(logging_setup, "configure_logging", lambda **kwargs: calls.append(kwargs))
    configure_cli_logging(context)
    assert len(calls) == 1
    assert calls[0]["force"] is True
    assert expected.items() <= calls[0].items()


def formatted_handlers() -> list[logging.Handler]:
    root = logging.getLogger()
    return [
        handler
        for handler in root.handlers
        if isinstance(handler.formatter, structlog.stdlib.ProcessorFormatter)
    ]


def test_configuring_twice_leaves_one_stderr_handler() -> None:
    configure_cli_logging(CliContext(verbosity=1))
    configure_cli_logging(CliContext(verbosity=2))
    assert formatted_handlers() == [log_config._handler]
    assert log_config._handler is not None
    assert log_config._handler.level == logging.DEBUG


def test_default_run_hides_info_and_verbose_shows_it(cli: Cli, probe: None) -> None:
    default = cli(["probe"])
    verbose = cli(["probe", "-v"])
    assert default.exit_code == verbose.exit_code == 0
    assert events(default) == {"probe_warning", "probe_error"}
    assert events(verbose) == {"probe_info", "probe_warning", "probe_error"}
    assert default.stdout == verbose.stdout == "RESULT\n"


def test_third_party_loggers_need_three_v(cli: Cli, probe: None) -> None:
    assert events(cli(["-vv", "probe"])) == {
        "probe_debug",
        "probe_info",
        "probe_warning",
        "probe_error",
    }
    assert "third_party_debug" in events(cli(["-vvv", "probe"]))
    assert events(cli(["--debug", "probe"])) >= {"probe_debug"}


def test_quiet_and_explicit_level(cli: Cli, probe: None) -> None:
    assert events(cli(["--quiet", "probe"])) == {"probe_error"}
    assert events(cli(["-v", "--log-level", "error", "probe"])) == {"probe_error"}
    assert events(cli(["probe"], env={"CODEKAVACH_LOG_LEVEL": "info"})) >= {"probe_info"}
    bad = cli(["--log-level", "loud", "probe"])
    assert bad.exit_code == 2


def test_secret_shaped_values_are_redacted_on_stderr(cli: Cli, probe: None) -> None:
    result = cli(["probe"])
    assert "probe_warning" in result.stderr
    assert AWS_EXAMPLE_KEY not in result.stderr
    assert "redacted" in result.stderr


def test_json_format_on_stderr_and_clean_stdout(cli: Cli, probe: None) -> None:
    result = cli(["--log-format", "json", "--log-level", "debug", "probe"])
    assert result.stdout == "RESULT\n"
    lines = [json.loads(line) for line in result.stderr.splitlines() if line.strip()]
    assert {"probe_debug", "probe_error"} <= {line["event"] for line in lines}
    assert {line["level"] for line in lines} >= {"debug", "info", "warning", "error"}
    under_json = cli(["--json", "probe"])
    assert all(line.startswith("{") for line in under_json.stderr.splitlines() if line.strip())


def test_config_show_logs_only_to_stderr(cli: Cli, tmp_path: Path) -> None:
    command = typer.main.get_command(config_app)  # mounted on the root by E05-19
    attach_global_options(command)
    result = cli(
        ["show", "--log-format", "json", "--log-level", "debug"], command=command, cwd=tmp_path
    )
    assert result.exit_code == 0, result.stderr
    assert result.stdout.strip()
    for line in result.stderr.splitlines():
        if line.strip():
            assert isinstance(json.loads(line), dict)
    assert '"event"' not in result.stdout


def test_log_file_is_private_and_redacted(cli: Cli, probe: None, tmp_path: Path) -> None:
    target = tmp_path / "out.log"
    result = cli(["probe", "--log-file", str(target)])
    assert result.exit_code == 0, result.stderr
    text = target.read_text(encoding="utf-8")
    assert {"probe_debug", "probe_info", "probe_warning", "probe_error"} <= {
        name
        for name in ("probe_debug", "probe_info", "probe_warning", "probe_error")
        if name in text
    }
    assert AWS_EXAMPLE_KEY not in text
    assert "redacted" in text
    assert events(result) == {"probe_warning", "probe_error"}  # stderr keeps its own level
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    missing = cli(["probe", "--log-file", str(tmp_path / "absent" / "out.log")])
    assert missing.exit_code == 2


def test_existing_log_file_is_tightened_and_appended(cli: Cli, probe: None, tmp_path: Path) -> None:
    target = tmp_path / "out.log"
    target.write_text("earlier\n", encoding="utf-8")
    if os.name != "nt":
        target.chmod(0o644)
    assert cli(["probe", "--log-file", str(target)]).exit_code == 0
    assert target.read_text(encoding="utf-8").startswith("earlier\n")
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_logging_settings_apply_when_no_flag_chooses(cli: Cli, probe: None, tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "codekavach.toml").write_text('[logging]\nlevel = "debug"\n', encoding="utf-8")
    configured = cli(["probe", "--load"], cwd=tmp_path)
    assert "probe_debug" in events(configured)
    overridden = cli(["probe", "--load", "--quiet"], cwd=tmp_path)
    assert events(overridden) == {"probe_error"}
    (tmp_path / "codekavach.toml").write_text("", encoding="utf-8")
    assert events(cli(["probe", "--load"], cwd=tmp_path)) == {"probe_warning", "probe_error"}
