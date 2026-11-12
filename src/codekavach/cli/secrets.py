"""``codekavach secrets scan PATH [--history]``: find hard-coded credentials, masked (#236).

Runs the built-in secret detectors over the files of a directory (and, with ``--history``, over
the lines added by recent commits) and prints one row per hit: file, line, type, confidence and a
mask that shows at most the first two characters and the length. The value itself is never
printed, logged or put in the JSON envelope. Exit code 1 when anything was found, 0 otherwise.
Reads local files only; opens no connection.
"""

from pathlib import Path
from typing import Annotated, Any

import typer

from codekavach.cli.context import with_target
from codekavach.cli.errors import ThresholdExceeded, UsageError
from codekavach.cli.output import get_output, simple_table

secrets_app = typer.Typer(
    help="Find hard-coded credentials; values are always masked.", no_args_is_help=True
)

_SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".codekavach"}
_MAX_BYTES = 1_000_000


def _row(candidate: Any) -> dict[str, Any]:
    props = dict(candidate.properties)
    place = candidate.primary_location
    return {
        "path": place.path,
        "line": place.start_line,
        "type": props.get("secret.type", ""),
        "confidence": str(candidate.engine_confidence),
        "severity": str(candidate.engine_severity),
        "mask": props.get("secret.preview", ""),
        "commit": props.get("secret.commit"),
    }


@secrets_app.command("scan")
def scan_command(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Directory to scan.")] = Path(),
    history: Annotated[
        bool,
        typer.Option(
            "--history", help="Also scan lines added by past commits that are gone from the tree."
        ),
    ] = False,
) -> None:
    """Scan a directory for hard-coded credentials and print masked results."""
    from codekavach.analysis.secrets.history import scan_history  # noqa: PLC0415
    from codekavach.analysis.secrets.stage import (  # noqa: PLC0415
        candidates_for,
        hits_in,
        secret_registry,
    )
    from codekavach.core.models import Language  # noqa: PLC0415

    if not target.is_dir():
        raise UsageError(f"directory does not exist: {target}", code="target_not_found")
    settings = with_target(ctx, target).settings
    root = target.resolve()
    registry = secret_registry()
    found: list[Any] = []
    files = 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in _SKIP for part in rel.parts) or not path.is_file() or path.is_symlink():
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        files += 1
        hits = hits_in(
            raw.decode("utf-8", errors="replace"),
            rel.as_posix(),
            Language.UNKNOWN,
            settings,
            registry,
        )
        found.extend(candidates_for(rel.as_posix(), Language.UNKNOWN, hits))
    if history or settings.secrets.history:
        found.extend(
            scan_history(root, settings, registry, max_commits=settings.secrets.history_max_commits)
        )
    rows = [_row(c) for c in found]
    rows.sort(key=lambda r: (r["path"], r["line"], r["type"]))
    data = {
        "files_scanned": files,
        "history": history or settings.secrets.history,
        "findings": rows,
    }

    def human(console: Any) -> None:
        if not rows:
            console.print(f"No hard-coded credentials found in {files} files.")
            return
        console.print(
            simple_table(
                ["Where", "Type", "Confidence", "Mask", "Commit"],
                [
                    [
                        f"{r['path']}:{r['line']}",
                        r["type"],
                        r["confidence"],
                        r["mask"],
                        r["commit"] or "-",
                    ]
                    for r in rows
                ],
            )
        )
        console.print(
            f"{len(rows)} hit(s) in {files} files; values are masked. Rotate before deleting."
        )

    get_output(ctx).result(data, human=human)
    if rows:
        raise ThresholdExceeded(f"{len(rows)} hard-coded credential(s) found", code="secrets_found")
