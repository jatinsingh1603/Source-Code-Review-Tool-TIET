"""``codekavach suppress list``: every suppression of a project and its state (#240).

Lists the entries of the suppressions file (``aggregate.suppressions_file``) and the inline
``codekavach:ignore`` markers in the project's sources, with their justification. An entry or
marker without a justification, and an entry past its ``expires`` date, is shown as inactive
because it silences nothing. Exit code 1 when any inactive suppression exists, so a pipeline can
require a clean list. Read-only; a justification is the author's own text, never code.
"""

from pathlib import Path
from typing import Annotated, Any

import typer

from codekavach.cli.context import with_target
from codekavach.cli.errors import ThresholdExceeded, UsageError
from codekavach.cli.output import get_output, simple_table

suppress_app = typer.Typer(help="List the suppressions of a project.", no_args_is_help=True)

_SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".codekavach"}
_MAX_BYTES = 1_000_000


@suppress_app.command("list")
def list_command(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Project directory.")] = Path(),
) -> None:
    """List suppression-file entries and inline markers; exit 1 if any is inactive."""
    from codekavach.analysis.aggregate.suppress import (  # noqa: PLC0415
        describe_file_rules,
        inline_markers,
    )

    if not target.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    settings = with_target(ctx, target).settings
    root = target.resolve()
    rows = describe_file_rules(root / settings.aggregate.suppressions_file)
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in _SKIP for part in rel.parts) or not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rows.extend(inline_markers(text, rel.as_posix()))
    inactive = sum(1 for r in rows if r["state"] != "active")
    data = {
        "file": settings.aggregate.suppressions_file,
        "suppressions": rows,
        "inactive": inactive,
    }

    def human(console: Any) -> None:
        if not rows:
            console.print("No suppressions.")
            return
        console.print(
            simple_table(
                ["State", "Source", "Rule", "Where", "Expires", "Justification"],
                [
                    [
                        r["state"],
                        r["source"],
                        r["rule"],
                        r["path"],
                        r["expires"] or "-",
                        r["justification"] or "(none)",
                    ]
                    for r in rows
                ],
            )
        )

    get_output(ctx).result(data, human=human)
    if inactive:
        raise ThresholdExceeded(
            f"{inactive} suppression(s) are inactive", code="inactive_suppressions"
        )
