import errno
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from codekavach.cli.app import app
from codekavach.cli.backends import load_backend
from codekavach.cli.errors import (
    BackendUnavailableError,
    CliError,
    InternalError,
    PrivacyBlockError,
    ThresholdExceeded,
    UsageError,
)
from codekavach.cli.exit_codes import EXIT_CODE_HELP, ExitCode
from codekavach.config.errors import ConfigError, ConfigErrorCode, ConfigIssue
from codekavach.core.pipeline.cancel import ScanCancelledError
from tests.support.cli import CliResult

Cli = Callable[..., CliResult]
SECRET = "hunter2"  # pragma: allowlist secret
RAISE: list[BaseException] = []


@pytest.fixture
def boom() -> Iterator[None]:
    """A temporary ``boom`` command raising whatever ``RAISE`` holds."""

    def command() -> None:
        raise RAISE[0]

    app.command("boom")(command)
    try:
        yield
    finally:
        app.registered_commands[:] = [c for c in app.registered_commands if c.name != "boom"]
        RAISE.clear()


def invoke(cli: Cli, error: BaseException, *extra: str, **kwargs: object) -> CliResult:
    RAISE[:] = [error]
    return cli(["boom", *extra], **kwargs)


@pytest.mark.parametrize(
    ("error", "code", "pattern"),
    [
        (UsageError("bad input", code="bad_input"), 2, "error[bad_input]: bad input"),
        (BackendUnavailableError("ledger is missing"), 2, "error[backend_unavailable]"),
        (PrivacyBlockError("no consent", code="consent_missing"), 3, "error[consent_missing]"),
        (ThresholdExceeded(), 1, "error[threshold_exceeded]"),
        (InternalError("broken state"), 4, "error[internal]: broken state"),
        (KeyboardInterrupt(), 130, "cancelled"),
        (ScanCancelledError(), 130, "cancelled"),
        (RuntimeError("x"), 4, "unexpected RuntimeError; run again with --debug"),
    ],
)
def test_mapping(cli: Cli, boom: None, error: BaseException, code: int, pattern: str) -> None:
    result = invoke(cli, error)
    assert result.exit_code == code
    assert pattern in result.stderr
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


def test_hint_is_printed(cli: Cli, boom: None) -> None:
    result = invoke(cli, UsageError("missing", hint="pass --config"))
    assert result.stderr.splitlines() == ["error[usage]: missing", "hint: pass --config"]


def test_unknown_option(cli: Cli) -> None:
    result = cli(["--no-such-option"])
    assert result.exit_code == 2
    assert "No such option" in result.stderr
    assert result.stdout == ""


def test_secret_in_message_is_hidden(cli: Cli, boom: None) -> None:
    result = invoke(cli, RuntimeError(f"password={SECRET}"))
    assert result.exit_code == 4
    assert SECRET not in result.stdout
    assert SECRET not in result.stderr


@pytest.mark.parametrize(
    ("extra", "env"),
    [(("--debug",), {}), (("-vv",), {}), ((), {"CODEKAVACH_DEBUG": "1"})],
)
def test_traceback_on_request(
    cli: Cli, boom: None, extra: tuple[str, ...], env: dict[str, str]
) -> None:
    RAISE[:] = [RuntimeError(f"password={SECRET}")]
    result = cli([*extra, "boom"] if extra else ["boom"], env=env)
    assert result.exit_code == 4
    assert "Traceback" in result.stderr
    assert SECRET in result.stderr
    assert result.stdout == ""


def test_config_error(cli: Cli, boom: None) -> None:
    issues = [
        ConfigIssue(ConfigErrorCode.CK_CFG_003, "error", "bad jobs", key="scan.jobs"),
        ConfigIssue(ConfigErrorCode.CK_CFG_002, "error", "unknown key", key="scna"),
    ]
    result = invoke(cli, ConfigError(issues))
    assert result.exit_code == 2
    assert "error[config_invalid]" in result.stderr
    assert "scan.jobs" in result.stderr
    assert "scna" in result.stderr


@pytest.mark.parametrize("error", [BrokenPipeError(), BrokenPipeError(errno.EPIPE, "closed")])
def test_broken_pipe(cli: Cli, boom: None, error: BrokenPipeError) -> None:
    result = invoke(cli, error)
    assert (result.exit_code, result.stdout, result.stderr) == (0, "", "")


def test_egress_blocked(cli: Cli, boom: None, monkeypatch: pytest.MonkeyPatch) -> None:
    class EgressBlocked(Exception):  # noqa: N818 - mirrors the E12 name
        block_code = "consent_missing"

    import codekavach.cli.app as app_module  # noqa: PLC0415

    real = app_module._optional_class

    def seam(module: str, name: str) -> type[BaseException] | None:
        return EgressBlocked if name == "EgressBlocked" else real(module, name)

    monkeypatch.setattr(app_module, "_optional_class", seam)
    result = invoke(cli, EgressBlocked("free text with a path"))
    assert result.exit_code == 3
    assert "error[egress_blocked]: egress guard refused the request (consent_missing)" in (
        result.stderr
    )
    assert "free text" not in result.stderr


def test_exit_code_values() -> None:
    assert {int(code) for code in ExitCode} == {0, 1, 2, 3, 4, 130}


def test_cli_error_code_validation() -> None:
    with pytest.raises(ValueError, match="error code"):
        CliError("x", code="Bad Code")


def test_load_backend(tmp_path: Path, fake_site: Path) -> None:
    with pytest.raises(BackendUnavailableError) as error:
        load_backend("codekavach.nonexistent", "x", feature="ledger", epic="E12")
    assert error.value.hint == "delivered by epic E12"
    with pytest.raises(BackendUnavailableError):
        load_backend("codekavach.cli.app", "no_such_attribute", feature="x", epic="E0")
    (fake_site / "ck_nested_import.py").write_text("import ck_really_missing\n", encoding="utf-8")
    with pytest.raises(ModuleNotFoundError):
        load_backend("ck_nested_import", "x", feature="x", epic="E0")
    assert load_backend("codekavach.cli.exit_codes", "ExitCode", feature="x", epic="E0") is ExitCode


def test_help_epilog_matches_reference(cli: Cli) -> None:
    result = cli(["--help"])
    assert "Exit codes:" in result.stdout
    assert "PRIVACY_BLOCK" in result.stdout
    reference = Path(__file__).resolve().parents[3] / "docs" / "reference" / "exit-codes.md"
    assert f"```text\n{EXIT_CODE_HELP}\n```" in reference.read_text(encoding="utf-8")
