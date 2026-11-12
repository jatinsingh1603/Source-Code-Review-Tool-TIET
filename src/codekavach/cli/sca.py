"""``codekavach sca update|list`` and ``codekavach sbom``: dependency inventory and advisories (E19).

Owning epic: E19. ``sca update`` is the only command that opens a connection, and only to the
allow-listed public advisory hosts (``codekavach.analysis.sca.update``); it sends nothing about
the project and refuses ``--offline``. ``sbom`` and ``sca list`` read the working tree and the
local mirror only.
"""

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from codekavach.cli.context import get_context
from codekavach.cli.errors import UsageError
from codekavach.cli.output import get_output

sca_app = typer.Typer(
    help="Refresh the advisory mirror and list vulnerable dependencies.", no_args_is_help=True
)


def _gather(target: Path) -> dict[str, str]:
    from codekavach.analysis.sca.manifests import is_manifest_path  # noqa: PLC0415

    texts: dict[str, str] = {}
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for path in sorted(target.rglob("*")):
        rel = path.relative_to(target)
        if any(part in skip for part in rel.parts) or not path.is_file():
            continue
        if is_manifest_path(rel.as_posix()):
            texts[rel.as_posix()] = path.read_text("utf-8", errors="replace")
    return texts


@sca_app.command("update")
def update_command(
    ctx: typer.Context,
    ecosystem: Annotated[
        list[str] | None,
        typer.Option("--ecosystem", "-e", help="Ecosystem to mirror (repeatable)."),
    ] = None,
    kev: Annotated[
        bool, typer.Option("--kev/--no-kev", help="Fetch the CISA KEV catalogue.")
    ] = True,
    epss: Annotated[
        bool, typer.Option("--epss/--no-epss", help="Fetch the FIRST EPSS scores.")
    ] = True,
) -> None:
    """Download OSV snapshots, KEV and EPSS into the local data directory (the one network action)."""
    from codekavach.analysis.sca.advisories import default_mirror_dir  # noqa: PLC0415
    from codekavach.analysis.sca.update import (  # noqa: PLC0415
        DEFAULT_ECOSYSTEMS,
        OfflineError,
        update_mirror,
    )

    out = get_output(ctx)
    try:
        result = update_mirror(
            default_mirror_dir(),
            tuple(ecosystem or DEFAULT_ECOSYSTEMS),
            offline=get_context(ctx).offline,
            kev=kev,
            epss=epss,
        )
    except OfflineError as error:
        raise UsageError(str(error), code="offline_refused") from None
    data = {
        "directory": str(result.directory),
        "fetched": result.fetched,
        "failed": result.failed,
    }
    out.result(data, human=lambda console: console.print(json.dumps(data, indent=2)))
    if result.failed and not result.fetched:
        raise UsageError("no source could be fetched", code="sca_update_failed")


@sca_app.command("list")
def list_command(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Project directory.")] = Path(),
) -> None:
    """List the vulnerable dependencies of a project against the local mirror."""
    from codekavach.analysis.sca.advisories import (  # noqa: PLC0415
        default_mirror_dir,
        load_mirror,
        match,
    )
    from codekavach.analysis.sca.manifests import build_graph  # noqa: PLC0415

    graph, _ = build_graph(_gather(target))
    mirror = load_mirror(default_mirror_dir())
    rows: list[dict[str, Any]] = [
        {
            "package": m.dependency.name,
            "version": m.dependency.version,
            "advisory": m.advisory_id,
            "cve": m.cve,
            "severity": m.severity,
            "fixed": list(m.fixed),
        }
        for m in match(graph.dependencies, mirror)
    ]
    out = get_output(ctx)
    out.result(
        {"components": len(graph.dependencies), "vulnerable": rows},
        human=lambda console: console.print(
            "\n".join(
                f"{r['severity']:8} {r['package']} {r['version']}  {r['advisory']}  fixed: {', '.join(r['fixed']) or '-'}"
                for r in rows
            )
            or "No known vulnerable dependencies."
        ),
    )


def sbom_command(
    ctx: typer.Context,
    target: Annotated[Path, typer.Argument(help="Project directory.")] = Path(),
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="cyclonedx (default) or spdx.")
    ] = "cyclonedx",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write to this file instead of stdout.")
    ] = None,
) -> None:
    """Generate a CycloneDX 1.5 or SPDX 2.3 bill of materials from the manifests of a project."""
    from codekavach.analysis.sca.manifests import build_graph  # noqa: PLC0415
    from codekavach.analysis.sca.sbom import to_cyclonedx, to_spdx  # noqa: PLC0415

    if fmt not in {"cyclonedx", "spdx"}:
        raise UsageError("--format must be cyclonedx or spdx", code="bad_format")
    graph, _ = build_graph(_gather(target))
    name = target.resolve().name
    document = to_cyclonedx(graph, name) if fmt == "cyclonedx" else to_spdx(graph, name)
    text = json.dumps(document, indent=2)
    if output is None:
        typer.echo(text)
    else:
        output.write_text(text, encoding="utf-8")
        get_output(ctx).info(f"wrote {output} ({len(graph.dependencies)} components)")
