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
import importlib.util
import os
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Literal

import typer
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click
from typer._click.exceptions import NoArgsIsHelpError
from typer.core import TyperCommand, TyperGroup

from codekavach.cli import output
from codekavach.cli._version import get_version
from codekavach.cli.completion import COMPLETE_VAR, handle_request
from codekavach.cli.console import get_err_console
from codekavach.cli.errors import CliError, error_line, render_error
from codekavach.cli.exit_codes import EXIT_CODE_HELP, ExitCode
from codekavach.cli.options import attach_global_options
from codekavach.cli.signals import normalise_resume
from codekavach.core.log import configure_logging
from codekavach.core.no_telemetry import apply_opt_outs

# Typer 0.27 vendors Click as ``typer._click``; command objects and ``ClickException`` come from
# there, while ``Exit`` and ``Abort`` are ``typer.Exit`` and ``typer.Abort``.

HELP = "Privacy-preserving, LLM-assisted secure source code review."
EPILOG = EXIT_CODE_HELP
DEBUG_ENV = "CODEKAVACH_DEBUG"

# pretty_exceptions_enable must stay False: Rich tracebacks with locals would print client code,
# secrets or vault entries to the terminal on a crash.
# --- lazily resolved sub-commands (E05-31) --------------------------------------------------
#
# The root group knows its sub-commands from LAZY_COMMANDS (name, ``module:attribute`` target,
# kind, short help). A command module is imported only when the command runs or shows its own
# help, so ``--version``, ``--help`` and completion import no command module, no configuration
# loader and no Pydantic. Listing (root help, completion of names) uses placeholders carrying the
# short help; global options are attached on resolution; a target that fails to import is a
# ClickException naming the command.


@dataclass(frozen=True)
class LazyEntry:
    """One lazily imported sub-command."""

    name: str
    target: str  # "package.module:attribute"
    kind: Literal["command", "group"]
    short_help: str
    optional: bool = False  # skipped when its module does not exist (its epic has not landed)

    @property
    def module(self) -> str:
        """The dotted module of the target."""
        return self.target.partition(":")[0]

    @property
    def attribute(self) -> str:
        """The attribute of the target module."""
        return self.target.partition(":")[2]

    def available(self) -> bool:
        """Whether the target module exists (checked without importing it)."""
        if not self.optional:
            return True
        try:
            return importlib.util.find_spec(self.module) is not None
        except ModuleNotFoundError:
            return False


class LazyGroup(TyperGroup):
    """A Typer group whose sub-commands in ``LAZY_COMMANDS`` are imported on first use."""

    lazy_entries: Sequence[LazyEntry] = ()
    root_app: typer.Typer | None = None

    def _entry(self, name: str) -> LazyEntry | None:
        return next((e for e in self.lazy_entries if e.name == name and e.available()), None)

    def list_commands(self, ctx: click.Context) -> list[str]:
        """Eagerly registered commands first, then the lazy ones in table order."""
        lazy = [entry.name for entry in self.lazy_entries if entry.available()]
        eager = [name for name in self.commands if name not in lazy]
        return [*eager, *lazy]

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        """The command; a help placeholder while listing (help or completion of names)."""
        found = self.commands.get(cmd_name)
        if found is not None:
            return found
        entry = self._entry(cmd_name)
        if entry is None:
            return None
        if ctx.resilient_parsing or getattr(self, "_listing", False):
            return TyperCommand(name=entry.name, help=entry.short_help)
        return self.resolve_lazy(entry)

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        """Resolve the real command, also during completion (``scan --pr<TAB>`` needs options)."""
        if args:
            entry = self._entry(args[0])
            if entry is not None and args[0] not in self.commands:
                self.resolve_lazy(entry)
        return super().resolve_command(ctx, args)

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Root help lists the lazy commands from their placeholders, importing none of them."""
        self._listing = True
        try:
            super().format_help(ctx, formatter)
        finally:
            self._listing = False

    def resolve_lazy(self, entry: LazyEntry) -> click.Command:
        """Import ``entry``'s target, build its Click command and attach the global options."""
        try:
            module = importlib.import_module(entry.module)
            target: Any = getattr(module, entry.attribute)
        except (ImportError, AttributeError) as error:
            raise click.ClickException(
                f"command '{entry.name}' is not available in this build ({type(error).__name__})"
            ) from None
        command = self._build(entry, target)
        attach_global_options(command)
        self.commands[entry.name] = command
        return command

    def _build(self, entry: LazyEntry, target: Any) -> click.Command:
        from typer.main import get_command_from_info, get_group_from_info  # noqa: PLC0415
        from typer.models import CommandInfo, TyperInfo  # noqa: PLC0415

        app = self.root_app
        markup = app.rich_markup_mode if app is not None else "rich"
        short = app.pretty_exceptions_short if app is not None else True
        if isinstance(target, typer.Typer):
            group = get_group_from_info(
                TyperInfo(target, name=entry.name),
                pretty_exceptions_short=short,
                suggest_commands=app.suggest_commands if app is not None else True,
                rich_markup_mode=markup,
            )
            group.name = entry.name
            return group
        return get_command_from_info(
            CommandInfo(name=entry.name, callback=target),
            pretty_exceptions_short=short,
            rich_markup_mode=markup,
        )


# Every sub-command except ``version`` is imported on first use (E05-31): ``--version``,
# ``--help`` and completion import no command module. Short help is the first paragraph of the
# command's help; tests/unit/cli/test_lazy_group.py keeps the two in step.
LAZY_COMMANDS: tuple[LazyEntry, ...] = (
    LazyEntry("scan", "codekavach.cli.scan:scan_command", "command",
              "Scan a code base and print a severity summary."),
    LazyEntry("report", "codekavach.cli.report:report_command", "command",
              "Render the report of a stored scan."),
    LazyEntry("doctor", "codekavach.cli.doctor:doctor_command", "command",
              "Check that this machine is ready to scan."),
    LazyEntry("completion", "codekavach.cli.completion:completion_command", "command",
              "Print a shell completion script."),
    # The configuration commands are owned by E03 (codekavach.cli.config).
    LazyEntry("init", "codekavach.cli.config:init_command", "command",
              "Write a commented starter codekavach.toml rendered from the settings models.",
              optional=True),
    LazyEntry("privacy", "codekavach.cli.privacy:privacy_app", "group",
              "Inspect what is prepared for, and recorded as sent to, LLM providers."),
    LazyEntry("providers", "codekavach.cli.providers:providers_app", "group",
              "Inspect and test LLM providers."),
    LazyEntry("plugins", "codekavach.cli.plugins:plugins_app", "group",
              "Inspect installed plugins and check that their stages form a pipeline."),
    LazyEntry("vault", "codekavach.cli.vault:vault_app", "group",
              "Manage the local mapping vault. Its contents never appear in any output."),
    LazyEntry("config", "codekavach.cli.config:config_app", "group",
              "Inspect and manage configuration.", optional=True),
)  # fmt: skip


class RootGroup(LazyGroup):
    """The ``codekavach`` group with the lazy table above."""

    lazy_entries = LAZY_COMMANDS


app = typer.Typer(
    name="codekavach",
    cls=RootGroup,
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


def build_cli() -> click.Command:
    """The Click command tree of the application with the global options attached."""
    command = typer.main.get_command(app)
    RootGroup.root_app = app
    attach_global_options(command)  # root group and eager commands; lazy ones on resolution
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
    instruction = os.environ.get(COMPLETE_VAR)
    if instruction:  # a shell asks for candidates: answer before any processing or config load
        return handle_request(command, instruction)
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
    apply_opt_outs()  # first: before logging and before any engine or provider is touched
    configure_logging()
    return run(build_cli(), sys.argv[1:] if argv is None else argv)
