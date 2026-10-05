"""The root Typer application, the process entry point and the top-level error handler.

Owning epic: E05.

``main()`` is the console-script target: it performs the process-wide set-up first and then hands
the argument list to ``run()``, which executes the Click command with ``standalone_mode=False`` so
that one function turns every outcome into exactly one documented exit code (``exit_codes``).
Importing this module reads no configuration, touches no keyring and imports no pipeline code, so
``--help`` and ``--version`` are safe in any directory, including an untrusted repository.

Error rendering is conservative: messages of CodeKavach's own errors are printed; any other
exception is reported by its type only, because messages and tracebacks can quote client code,
paths or credentials. Tracebacks go to stderr only with ``--debug``, ``-vv`` or
``CODEKAVACH_DEBUG=1``. Nothing but the JSON envelope is ever written to stdout here.
"""

import contextlib
import errno
import importlib
import os
import sys
import traceback
from collections.abc import Sequence
from typing import Annotated

import typer
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click
from typer._click.exceptions import NoArgsIsHelpError

from codekavach.cli import output
from codekavach.cli._version import get_version
from codekavach.cli.console import get_err_console
from codekavach.cli.doctor import doctor_command
from codekavach.cli.errors import CliError, error_line, render_error
from codekavach.cli.exit_codes import EXIT_CODE_HELP, ExitCode
from codekavach.cli.options import attach_global_options
from codekavach.cli.privacy import privacy_app
from codekavach.cli.providers import providers_app
from codekavach.cli.report import report_command
from codekavach.cli.scan import scan_command
from codekavach.cli.signals import normalise_resume
from codekavach.core.log import configure_logging

# Typer 0.27 vendors Click as ``typer._click``; command objects and ``ClickException`` come from
# there, while ``Exit`` and ``Abort`` are ``typer.Exit`` and ``typer.Abort``.

HELP = "Privacy-preserving, LLM-assisted secure source code review."
EPILOG = EXIT_CODE_HELP
DEBUG_ENV = "CODEKAVACH_DEBUG"

# pretty_exceptions_enable must stay False: Rich tracebacks with locals would print client code,
# secrets or vault entries to the terminal on a crash.
app = typer.Typer(
    name="codekavach",
    help=HELP,
    epilog=EPILOG,
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"codekavach {get_version()}")
        raise typer.Exit(0)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Privacy-preserving, LLM-assisted secure source code review."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


@app.command("version")
def version_command() -> None:
    """Show the version and exit."""
    typer.echo(f"codekavach {get_version()}")


app.command("scan")(scan_command)
app.command("report")(report_command)
app.command("doctor")(doctor_command)
app.add_typer(privacy_app, name="privacy")
app.add_typer(providers_app, name="providers")


def _mount(name: str, dotted: str, attr: str) -> bool:
    """Register ``dotted.attr`` on the root application as ``name``; skip it when absent.

    A sub-application is added as a group, a function as a command. A module that does not
    exist (its epic has not landed) or lacks the attribute is skipped without an error, so the
    group simply does not exist; an ``ImportError`` raised inside an existing module propagates.
    """
    try:
        module = importlib.import_module(dotted)
    except ModuleNotFoundError as error:
        if error.name is not None and (dotted == error.name or dotted.startswith(f"{error.name}.")):
            return False
        raise
    target = getattr(module, attr, None)
    if target is None:
        return False
    if isinstance(target, typer.Typer):
        app.add_typer(target, name=name)
    else:
        app.command(name)(target)
    return True


# The configuration commands are owned by E03 (codekavach.cli.config); this is their only mount.
_mount("config", "codekavach.cli.config", "config_app")
_mount("init", "codekavach.cli.config", "init_command")


def build_cli() -> click.Command:
    """The Click command tree of the application with the global options attached."""
    command = typer.main.get_command(app)
    attach_global_options(command)
    return command


def _flags(argv: Sequence[str]) -> tuple[bool, int, bool]:
    """``(debug, verbosity, json_mode)`` read from ``argv`` and the environment."""
    verbosity = 0
    for arg in argv:
        if arg == "--verbose":
            verbosity += 1
        elif arg.startswith("-") and not arg.startswith("--") and set(arg[1:]) == {"v"}:
            verbosity += len(arg) - 1
    debug = "--debug" in argv or verbosity >= 2 or os.environ.get(DEBUG_ENV) == "1"
    return debug, verbosity, "--json" in argv


def _traceback(error: BaseException, debug: bool) -> None:
    if debug:
        text = "".join(traceback.format_exception(error))
        get_err_console().print(text, markup=False, highlight=False, end="")


def _optional_class(module: str, name: str) -> type[BaseException] | None:
    try:
        imported = __import__(module, fromlist=[name])
    except ImportError:
        return None
    found = getattr(imported, name, None)
    return found if isinstance(found, type) and issubclass(found, BaseException) else None


def _quiet_stdout() -> None:
    """After a broken pipe, point stdout at the null device so that nothing more fails."""
    with contextlib.suppress(OSError, ValueError, AttributeError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())


def _handle(error: BaseException, argv: Sequence[str]) -> int:  # noqa: PLR0911
    """Map an exception raised by a command to its exit code, rendering it once."""
    debug, verbosity, json_mode = _flags(argv)
    cancelled = _optional_class("codekavach.core.pipeline.cancel", "ScanCancelledError")
    config_error = _optional_class("codekavach.config.errors", "ConfigError")
    egress_blocked = _optional_class("codekavach.privacy.egress.guard", "EgressBlocked")
    if isinstance(error, typer.Exit):
        return int(error.exit_code or 0)
    if isinstance(error, NoArgsIsHelpError):
        return ExitCode.OK  # Typer has already printed the help
    if isinstance(error, click.ClickException):
        if json_mode:
            output.write_error_envelope(code="usage", message=error.format_message(), hint=None)
        else:
            error.show()
        return ExitCode.USAGE
    if isinstance(error, typer.Abort | KeyboardInterrupt) or (
        cancelled is not None and isinstance(error, cancelled)
    ):
        get_err_console().print("cancelled", markup=False)
        return ExitCode.CANCELLED
    if isinstance(error, BrokenPipeError):
        _quiet_stdout()
        return ExitCode.OK
    if isinstance(error, CliError):
        render_error(error, verbosity=verbosity, json_mode=json_mode)
        _traceback(error, debug)
        return int(error.exit_code)
    if config_error is not None and isinstance(error, config_error):
        get_err_console().print(error_line("config_invalid", str(error)), markup=False)
        _traceback(error, debug)
        return ExitCode.USAGE
    if egress_blocked is not None and isinstance(error, egress_blocked):
        block = getattr(error, "block_code", "unknown")
        message = f"egress guard refused the request ({block})"
        get_err_console().print(error_line("egress_blocked", message), markup=False)
        return ExitCode.PRIVACY_BLOCK
    if isinstance(error, Exception):
        render_error(error, verbosity=verbosity, json_mode=json_mode)
        _traceback(error, debug)
        return ExitCode.INTERNAL
    raise error


def _command_from_argv(command: click.Command, argv: Sequence[str]) -> str:
    """Best-effort command path for errors raised before any command body ran."""
    path: list[str] = []
    node = command
    for token in argv:
        children: dict[str, click.Command] = getattr(node, "commands", {}) or {}
        if token in children:
            path.append(token)
            node = children[token]
    return " ".join(path)


def run(command: click.Command, argv: Sequence[str]) -> int:
    """Execute ``command`` with ``argv``, write the JSON envelope if any, return the exit code."""
    output.begin_invocation()
    argv = normalise_resume(argv)  # ``--resume`` without a value means the latest scan
    code = _execute(command, argv)
    found = output.current_output()
    if found is None and _flags(argv)[2]:
        found = output.fallback_output(json_mode=True, command=_command_from_argv(command, argv))
    if found is not None:
        found.finish(code)
    return code


def _execute(command: click.Command, argv: Sequence[str]) -> int:
    """Run the command and map every outcome to an exit code."""
    try:
        result = command.main(args=list(argv), prog_name="codekavach", standalone_mode=False)
    except SystemExit as exit_:
        # Typer turns a broken pipe (EPIPE) into sys.exit(1); a closed pipe is not an error.
        context = exit_.__context__
        if isinstance(context, OSError) and context.errno == errno.EPIPE:
            _quiet_stdout()
            return ExitCode.OK
        raise
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - the single top-level handler
        return _handle(error, argv)
    code = int(result) if isinstance(result, int) else ExitCode.OK
    if code == ExitCode.CANCELLED:  # Typer returns 130 for KeyboardInterrupt
        get_err_console().print("cancelled", markup=False)
    return code


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point: process-wide set-up, then run the command line."""
    configure_logging()
    return run(build_cli(), sys.argv[1:] if argv is None else argv)
