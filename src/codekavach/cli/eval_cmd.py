"""``codekavach eval detection|leakage``: the evaluation harnesses (E05-27).

Owning epic: E05.

The grammar is fixed here so that the evaluation scripts can be written against it. The back ends
are ``codekavach.eval.run_detection_eval`` (epic E36) and ``codekavach.eval.run_leakage_eval``
(epic E37). Until they land, a command validates its arguments and ends with
``backend_unavailable``; it prints no metric and writes no file.
"""

from typing import Annotated

import typer

from codekavach.cli.deferred import (
    check_dataset,
    check_levels,
    check_names,
    check_scan,
    run_backend,
)
from codekavach.cli.errors import UsageError

eval_app = typer.Typer(help="Run the detection and leakage evaluations.", no_args_is_help=True)

LEVEL_HELP = "Privacy level to evaluate; repeat for several (L0 to L4)."


@eval_app.command("detection")
def detection_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    dataset: Annotated[
        str,
        typer.Option("--dataset", metavar="NAME_OR_PATH", help="Benchmark dataset to evaluate on."),
    ],
    level: Annotated[
        list[str] | None, typer.Option("--level", metavar="Lx", help=LEVEL_HELP)
    ] = None,
    provider: Annotated[
        list[str] | None,
        typer.Option("--provider", metavar="ID", help="Provider to evaluate; repeat for several."),
    ] = None,
    out: Annotated[
        str | None, typer.Option("--out", metavar="PATH", help="Where to write the results.")
    ] = None,
    limit: Annotated[
        int | None,
        typer.Option("--limit", min=1, help="Evaluate at most this many cases."),
    ] = None,
) -> None:
    """Measure detection quality (precision, recall) on a benchmark dataset.

    Runs the scan on a labelled dataset at each requested privacy level and with each requested
    provider, and compares the findings with the labels. Delivered by epic E36.
    """
    levels = check_levels(level or [])
    check_dataset(dataset)
    providers = check_names(provider or [], option="--provider")
    run_backend(
        ctx,
        module="codekavach.eval",
        attribute="run_detection_eval",
        feature="the detection evaluation",
        epic="E36",
        arguments={
            "dataset": dataset,
            "levels": levels,
            "providers": providers,
            "out": out,
            "limit": limit,
        },
    )


@eval_app.command("leakage")
def leakage_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    scan: Annotated[
        str | None,
        typer.Option("--scan", metavar="[SCAN_ID|latest]", help="A stored scan to attack."),
    ] = None,
    dataset: Annotated[
        str | None,
        typer.Option("--dataset", metavar="NAME_OR_PATH", help="A dataset to prepare and attack."),
    ] = None,
    level: Annotated[
        list[str] | None, typer.Option("--level", metavar="Lx", help=LEVEL_HELP)
    ] = None,
    attacker: Annotated[
        list[str] | None,
        typer.Option("--attacker", metavar="NAME", help="Attack to run; repeat for several."),
    ] = None,
    out: Annotated[
        str | None, typer.Option("--out", metavar="PATH", help="Where to write the results.")
    ] = None,
) -> None:
    """Measure what a curious provider could reconstruct from the prepared payloads.

    Attacks the payloads of a stored scan, or of a dataset, at each requested privacy level and
    reports how much an attacker recovers. Takes --scan or --dataset, not both; without either it
    uses the latest scan. Delivered by epic E37.
    """
    if scan is not None and dataset is not None:
        raise UsageError("give --scan or --dataset, not both", code="scan_dataset_conflict")
    if scan is not None:
        check_scan(scan)
    if dataset is not None:
        check_dataset(dataset)
    levels = check_levels(level or [])
    attackers = check_names(attacker or [], option="--attacker")
    run_backend(
        ctx,
        module="codekavach.eval",
        attribute="run_leakage_eval",
        feature="the leakage evaluation",
        epic="E37",
        arguments={
            "scan": scan if scan is not None or dataset is not None else "latest",
            "dataset": dataset,
            "levels": levels,
            "attackers": attackers,
            "out": out,
        },
    )
