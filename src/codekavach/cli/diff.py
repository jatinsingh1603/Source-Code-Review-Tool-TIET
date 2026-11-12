"""``codekavach diff SCAN_A SCAN_B``: what changed between two stored scans (#240).

Compares the finding fingerprints of the two scans of a project and reports which are new in
``SCAN_B``, which are fixed (in ``SCAN_A`` only) and which are unchanged. Either argument may be
``latest``. Prints titles, severities and locations of findings, never evidence. Exit code 1 when
there are new findings, so a pipeline can gate on regressions; 0 otherwise.
"""

from pathlib import Path
from typing import Annotated, Any

import typer

from codekavach.cli.context import get_context, with_target
from codekavach.cli.errors import ThresholdExceeded, UsageError
from codekavach.cli.output import get_output, simple_table


def _brief(finding: dict[str, Any]) -> dict[str, Any]:
    place = finding["locations"][0]
    return {
        "fingerprint": finding["fingerprint"],
        "title": finding["title"],
        "severity": finding["severity"],
        "path": place["path"],
        "line": place["start_line"],
    }


def diff_command(
    ctx: typer.Context,
    scan_a: Annotated[str, typer.Argument(help="The earlier scan id, or latest.")],
    scan_b: Annotated[str, typer.Argument(help="The later scan id, or latest.")],
    target: Annotated[
        Path, typer.Option("--target", "-t", help="Project directory the scans belong to.")
    ] = Path(),
) -> None:
    """Show the findings that are new, fixed and unchanged between two stored scans."""
    from codekavach.analysis.aggregate.delta import compute_delta  # noqa: PLC0415
    from codekavach.integrations.store import ScanNotFoundError, load_scan  # noqa: PLC0415

    if not target.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    settings = with_target(ctx, target).settings
    get_context(ctx)
    try:
        first = load_scan(target, settings, scan_a)
        second = load_scan(target, settings, scan_b)
    except ScanNotFoundError as error:
        raise UsageError(str(error), code="scan_not_found") from None
    delta = compute_delta(
        (f["fingerprint"] for f in first.findings), (f["fingerprint"] for f in second.findings)
    )
    by_fingerprint = {f["fingerprint"]: f for f in [*first.findings, *second.findings]}

    def rows(fingerprints: tuple[str, ...]) -> list[dict[str, Any]]:
        return [_brief(by_fingerprint[fp]) for fp in fingerprints]

    data: dict[str, Any] = {
        "from": first.scan_id,
        "to": second.scan_id,
        "counts": delta.as_dict(),
        "new": rows(delta.new),
        "fixed": rows(delta.fixed),
        "unchanged": len(delta.unchanged),
    }

    def human(console: Any) -> None:
        console.print(
            f"{first.scan_id} -> {second.scan_id}: {len(delta.new)} new, "
            f"{len(delta.fixed)} fixed, {len(delta.unchanged)} unchanged"
        )
        for label, items in (("New", data["new"]), ("Fixed", data["fixed"])):
            if items:
                console.print(label)
                console.print(
                    simple_table(
                        ["Severity", "Where", "Title"],
                        [[i["severity"], f"{i['path']}:{i['line']}", i["title"]] for i in items],
                    )
                )

    get_output(ctx).result(data, human=human)
    if delta.new:
        raise ThresholdExceeded(f"{len(delta.new)} new finding(s)", code="new_findings")
