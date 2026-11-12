"""``codekavach findings``: print the findings of a stored scan for tools (IDE, scripts).

Owning epic: E35.

Read-only. The output is metadata plus the evidence lines the scan already holds; nothing is
read from the vault, so pseudonymised originals and secrets never appear. ``--format sarif``
prints a SARIF 2.1.0 log for code-scanning tools.
"""

import json
from pathlib import Path
from typing import Annotated

import typer

from codekavach.cli.context import get_context, with_target
from codekavach.cli.errors import UsageError
from codekavach.cli.output import get_output

SEVERITIES = ("info", "low", "medium", "high", "critical")


def findings_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Project directory.")] = ".",
    scan: Annotated[str, typer.Option("--scan", help="Scan id or latest.")] = "latest",
    min_severity: Annotated[
        str, typer.Option("--min-severity", help="Lowest severity to include.")
    ] = "info",
    output_format: Annotated[
        str, typer.Option("--format", help="json (use with --json) or sarif.")
    ] = "json",
) -> None:
    """Print the findings of a stored scan (metadata and masked evidence only)."""
    from codekavach.integrations.store import ScanNotFoundError, load_scan  # noqa: PLC0415

    path = Path(target)
    if not path.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    if min_severity not in SEVERITIES:
        raise UsageError(
            "--min-severity must be one of " + ", ".join(SEVERITIES), code="bad_severity"
        )
    settings = with_target(ctx, path).settings
    get_context(ctx)
    try:
        stored = load_scan(path, settings, scan)
    except ScanNotFoundError as error:
        raise UsageError(str(error), code="scan_not_found") from None
    floor = SEVERITIES.index(min_severity)
    items = [f for f in stored.findings if SEVERITIES.index(f["severity"]) >= floor]
    if output_format == "sarif":
        from codekavach.integrations.github.findings import normalize_all  # noqa: PLC0415
        from codekavach.integrations.github.sarif import build_sarif  # noqa: PLC0415

        typer.echo(json.dumps(build_sarif(normalize_all(items))))
        return
    if output_format != "json":
        raise UsageError("--format must be json or sarif", code="bad_format")
    get_output(ctx).result(
        {"scan_id": stored.scan_id, "summary": stored.summary, "findings": items}
    )
