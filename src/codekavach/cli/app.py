"""Minimal Typer application so the console entry point resolves.

E05-02 replaces this module with the real application. It must keep ``main()``
as the console-script target: ``main()`` is the one place where process-wide
set-up happens before Typer parses arguments, and it ends by calling ``app()``.
"""

from typing import Annotated

import typer

from codekavach import __version__
from codekavach.core.log import configure_logging

# pretty_exceptions_show_locals must stay False: Rich tracebacks with locals would
# print client code, secrets or vault entries to the terminal on a crash.
app = typer.Typer(
    name="codekavach",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"codekavach {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Privacy-preserving, LLM-assisted secure source code review."""


@app.command("version")
def version_command() -> None:
    """Show the version and exit."""
    typer.echo(f"codekavach {__version__}")


def main() -> None:
    """Console-script entry point: process-wide set-up, then the Typer app."""
    configure_logging()
    app()
