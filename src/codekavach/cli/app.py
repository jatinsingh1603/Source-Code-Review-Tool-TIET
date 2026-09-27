"""The root Typer application and the process entry point.

Owning epic: E05.

``main()`` is the console-script target: it performs the process-wide set-up first and then hands
the argument list to ``run()``, which executes the Click command with ``standalone_mode=False`` so
that one function decides the exit code (a public contract, E05-04). Importing this module reads
no configuration, touches no keyring and imports no pipeline code, so ``--help`` and ``--version``
are safe in any directory, including an untrusted repository.
"""

import sys
from collections.abc import Sequence
from typing import Annotated

import typer
from typer import _click as click  # Typer >= 0.27 ships its own copy of Click
from typer._click.exceptions import NoArgsIsHelpError

from codekavach.cli._version import get_version
from codekavach.core.log import configure_logging

# Typer 0.27 vendors Click as ``typer._click``; command objects and ``ClickException`` come from
# there, while ``Exit`` and ``Abort`` are ``typer.Exit`` and ``typer.Abort``.

HELP = "Privacy-preserving, LLM-assisted secure source code review."
EPILOG = ""  # E05-04 fills this with the exit-code table.

# pretty_exceptions_enable must stay False: Rich tracebacks with locals would print client code,
# secrets or vault entries to the terminal on a crash.
app = typer.Typer(
    name="codekavach",
    help=HELP,
    epilog=EPILOG or None,
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
    """The Click command tree of the application (later issues post-process it here)."""
    return typer.main.get_command(app)


def run(command: click.Command, argv: Sequence[str]) -> int:
    """Execute ``command`` with ``argv`` and return the process exit code."""
    try:
        result = command.main(args=list(argv), prog_name="codekavach", standalone_mode=False)
    except typer.Exit as exit_:
        return int(exit_.exit_code or 0)
    except NoArgsIsHelpError as help_request:
        # ``no_args_is_help``: Typer has already printed the help; exit 0 as for ``--help``.
        del help_request
        return 0
    except click.ClickException as error:
        error.show()
        return 2
    except typer.Abort:
        return 130
    return int(result) if isinstance(result, int) else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point: process-wide set-up, then run the command line."""
    configure_logging()
    return run(build_cli(), sys.argv[1:] if argv is None else argv)
