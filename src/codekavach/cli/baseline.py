"""``codekavach baseline create|show|clear``: the findings a team has accepted as known (#240).

``create`` records the fingerprints of a stored scan in the baseline file
(``aggregate.baseline_file``, default ``.codekavach/baseline.json``); later scans report those
findings as known instead of new. The file holds fingerprints, rule ids and locations, never code
or secret values. ``show`` and ``clear`` read and delete it. Nothing here opens a connection.
"""

from pathlib import Path
from typing import Annotated, Any

import typer

from codekavach.cli.context import get_context, with_target
from codekavach.cli.errors import UsageError
from codekavach.cli.output import get_output, simple_table

baseline_app = typer.Typer(
    help="Record, show and clear the baseline of accepted findings.", no_args_is_help=True
)

TargetArg = Annotated[Path, typer.Argument(help="Project directory.")]


def _baseline_path(ctx: typer.Context, target: Path) -> Path:
    if not target.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    settings = with_target(ctx, target).settings
    return target.resolve() / settings.aggregate.baseline_file


def _rule_id(finding: dict[str, Any]) -> str:
    engines = (finding.get("provenance") or {}).get("engines") or []
    first = engines[0] if engines else {}
    return str(first.get("rule_id", "")) if isinstance(first, dict) else ""


@baseline_app.command("create")
def create_command(
    ctx: typer.Context,
    target: TargetArg = Path(),
    scan: Annotated[str, typer.Option("--scan", help="Scan id or latest.")] = "latest",
    force: Annotated[bool, typer.Option("--force", help="Replace an existing baseline.")] = False,
) -> None:
    """Record the findings of a stored scan as the baseline."""
    from codekavach.analysis.aggregate.baseline import write_entries  # noqa: PLC0415
    from codekavach.integrations.store import ScanNotFoundError, load_scan  # noqa: PLC0415

    path = _baseline_path(ctx, target)
    if path.exists() and not force:
        raise UsageError(
            f"a baseline already exists at {path.name}; pass --force to replace it",
            code="baseline_exists",
        )
    settings = get_context(ctx).settings
    try:
        stored = load_scan(target, settings, scan)
    except ScanNotFoundError as error:
        raise UsageError(str(error), code="scan_not_found") from None
    entries = [
        {
            "fingerprint": str(f["fingerprint"]),
            "rule_id": _rule_id(f),
            "path": str(f["locations"][0]["path"]),
            "line": str(f["locations"][0]["start_line"]),
        }
        for f in stored.findings
    ]
    count = write_entries(path, entries)
    name = str(path.relative_to(target.resolve()))
    data = {"file": name, "scan_id": stored.scan_id, "entries": count}
    get_output(ctx).result(
        data,
        human=lambda console: console.print(f"Baseline of {count} findings written to {name}."),
    )


@baseline_app.command("show")
def show_command(ctx: typer.Context, target: TargetArg = Path()) -> None:
    """List the entries of the baseline."""
    from codekavach.analysis.aggregate.baseline import load_baseline  # noqa: PLC0415

    path = _baseline_path(ctx, target)
    entries = load_baseline(path)
    rows = [
        {
            "fingerprint": fp,
            "rule_id": e.get("rule_id", ""),
            "path": e.get("path", ""),
            "line": e.get("line", ""),
        }
        for fp, e in sorted(entries.items(), key=lambda kv: (kv[1].get("path", ""), kv[0]))
    ]
    exists = path.exists()
    data = {"file": str(path.relative_to(target.resolve())), "exists": exists, "entries": rows}

    def human(console: Any) -> None:
        if not rows:
            console.print("The baseline is empty." if exists else "No baseline.")
            return
        console.print(
            simple_table(
                ["Path", "Line", "Rule", "Fingerprint"],
                [[r["path"], r["line"], r["rule_id"], r["fingerprint"][:20]] for r in rows],
            )
        )

    get_output(ctx).result(data, human=human)


@baseline_app.command("clear")
def clear_command(ctx: typer.Context, target: TargetArg = Path()) -> None:
    """Delete the baseline; every finding counts as new again."""
    path = _baseline_path(ctx, target)
    removed = path.exists()
    if removed:
        path.unlink()
    data = {"file": str(path.relative_to(target.resolve())), "removed": removed}
    get_output(ctx).result(
        data,
        human=lambda console: console.print(
            "Baseline removed." if removed else "No baseline to remove."
        ),
    )
