"""``codekavach demo``: the Demo 1 sequence on the mock provider (E05-27).

Owning epic: E05.

The grammar is fixed here; the runner is ``codekavach.cli.demo_runner.run_demo`` of epic E13. The
demo uses the mock provider, so no consent is involved, and its runner refuses a remote provider.
"""

from pathlib import Path
from typing import Annotated

import typer

from codekavach.cli.deferred import check_dataset, run_backend

DEFAULT_FIXTURE = "kavachbank"
DEFAULT_OUT = "codekavach-demo/"


def demo_command(
    ctx: typer.Context,
    fixture: Annotated[
        str,
        typer.Option("--fixture", metavar="NAME_OR_PATH", help="The sample project to scan."),
    ] = DEFAULT_FIXTURE,
    out: Annotated[
        str, typer.Option("--out", metavar="PATH", help="Directory for the demo output.")
    ] = DEFAULT_OUT,
    keep_state: Annotated[
        bool, typer.Option("--keep-state", help="Keep the state directory after the demo.")
    ] = False,
) -> None:
    """Run the Demo 1 sequence offline on the mock provider.

    Runs, in order: a scan of the fixture, the inspection page, the ledger verification with the
    zero-leak check and the report, and writes the results below --out. Nothing leaves the machine.
    Fails when a listed term occurs in a ledger payload.
    """
    check_dataset(fixture, option="--fixture")
    run_backend(
        ctx,
        module="codekavach.cli.demo_runner",
        attribute="run_demo",
        feature="the demo",
        epic="E13",
        arguments={"fixture": fixture, "out": Path(out), "keep_state": keep_state},
    )
