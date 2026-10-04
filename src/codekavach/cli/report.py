"""``codekavach report``: render the report of a stored scan in further formats (E05-15).

Owning epic: E05.

The command owns option parsing, the lookup of the stored scan and the listing of what was
written. Content and rendering belong to later epics and are reached through ``load_backend``:
the report document (E30) and the renderers (E31). A build without them exits 2 with
``backend_unavailable``; the command never simulates a report.

Reports contain client code (snippets with real names) and stay inside the client's environment.
Files are written with mode ``0o640`` below a directory created with ``0o750``. The command
prints and serialises paths, sizes and hashes only, never file content, and it withholds the text
of renderer errors, which may quote report content. It works from already restored findings and
does not open the vault (I3): a scan without readable findings is refused as ``scan_incomplete``.
"""

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final, Protocol

import typer
from rich.console import Console
from rich.table import Table

from codekavach.cli.backends import load_backend
from codekavach.cli.context import with_target
from codekavach.cli.errors import InternalError, UsageError
from codekavach.cli.output import TABLE_BOX, get_output

if TYPE_CHECKING:
    from codekavach.core.models.finding import Finding
    from codekavach.core.models.scan import Scan

LATEST: Final = "latest"
REPORT_DIR_MODE: Final = 0o750
REPORT_FILE_MODE: Final = 0o640
DOCTOR_HINT: Final = "run 'codekavach doctor --category report'"
DEFAULT_REASON: Final = "render_error"
_KILO: Final = 1000


class ScanLookup(Protocol):
    """Read access to the stored scans of one project."""

    def latest(self, project_root: Path) -> "Scan | None":
        """The newest completed scan of the project at ``project_root``."""

    def get(self, scan_id: str) -> "Scan | None":
        """The scan with ``scan_id``."""

    def findings(self, scan_id: str) -> "Sequence[Finding] | None":
        """The restored findings of the scan; ``None`` when the scan stored none."""


class Renderer(Protocol):
    """One output format (E31)."""

    extension: str

    def render(self, document: object, destination: Path) -> None:
        """Write ``document`` to ``destination``."""


class RendererRegistry(Protocol):
    """The installed renderers, built-in and from the ``codekavach.renderers`` plugins."""

    def names(self) -> Sequence[str]:
        """The format names that can be rendered."""

    def get(self, name: str) -> Renderer:
        """The renderer of ``name``."""


@dataclass(frozen=True)
class RenderedFile:
    """One requested format: the written file, or why it was not written."""

    format: str
    path: Path
    size_bytes: int | None = None
    sha256: str | None = None
    status: str = "written"
    reason_code: str | None = None

    def to_json(self) -> dict[str, Any]:
        """The entry of ``data.files``."""
        entry: dict[str, Any] = {
            "format": self.format,
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "status": self.status,
        }
        if self.reason_code is not None:
            entry["reason_code"] = self.reason_code
            entry["hint"] = DOCTOR_HINT
        return entry


def parse_formats(values: Sequence[str]) -> tuple[str, ...]:
    """``["HTML, pdf", "html"]`` gives ``("html", "pdf")``: split, strip, lower, first wins."""
    seen: dict[str, None] = {}
    for value in values:
        for part in value.split(","):
            name = part.strip().lower()
            if name:
                seen.setdefault(name)
    return tuple(seen)


def check_formats(requested: Sequence[str], registry: RendererRegistry) -> None:
    """Raise ``unknown_format`` for a name that no renderer provides."""
    known = sorted(registry.names())
    unknown = [name for name in requested if name not in known]
    if unknown:
        raise UsageError(
            f"unknown report format: {', '.join(unknown)}",
            code="unknown_format",
            hint=f"available formats: {', '.join(known)}",
        )


def check_output_dir(output_dir: Path, state_dir: Path) -> Path:
    """The resolved output directory; a file or a place inside the state directory is refused."""
    resolved = output_dir.resolve()
    if resolved.is_file():
        raise UsageError("--output-dir is a file", code="output_dir_invalid")
    if resolved == state_dir.resolve() or resolved.is_relative_to(state_dir.resolve()):
        raise UsageError(
            "--output-dir must not be inside the state directory", code="output_dir_invalid"
        )
    return resolved


def human_size(size: int) -> str:
    """``412 kB``, ``1.1 MB``."""
    if size < _KILO:
        return f"{size} B"
    if size < _KILO * _KILO:
        return f"{size / _KILO:.0f} kB"
    return f"{size / (_KILO * _KILO):.1f} MB"


def display_path(path: Path) -> str:
    """``path`` relative to the working directory when it is below it, with forward slashes."""
    try:
        return path.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(path)


def render_one(
    renderer: Renderer, name: str, document: object, destination: Path, *, overwrite: bool
) -> RenderedFile:
    """Render one format; a failure becomes an entry with a reason code and no error text."""
    if destination.exists() and not overwrite:
        return RenderedFile(name, destination, status="failed", reason_code="file_exists")
    try:
        renderer.render(document, destination)
        data = destination.read_bytes()
        if os.name != "nt":
            destination.chmod(REPORT_FILE_MODE)
    except Exception as error:  # noqa: BLE001 - the text may quote report content
        reason = getattr(error, "reason_code", None)
        code = reason if isinstance(reason, str) and reason.isidentifier() else DEFAULT_REASON
        return RenderedFile(name, destination, status="failed", reason_code=code)
    return RenderedFile(name, destination, len(data), hashlib.sha256(data).hexdigest())


def render_all(
    registry: RendererRegistry,
    formats: Sequence[str],
    document: object,
    *,
    output_dir: Path,
    stem: str,
    overwrite: bool,
    fail_fast: bool,
) -> list[RenderedFile]:
    """Render ``formats`` in order; continue after a failure unless ``fail_fast``."""
    output_dir.mkdir(mode=REPORT_DIR_MODE, parents=True, exist_ok=True)
    files: list[RenderedFile] = []
    for name in formats:
        renderer = registry.get(name)
        destination = output_dir / f"{stem}.{renderer.extension.lstrip('.')}"
        files.append(render_one(renderer, name, document, destination, overwrite=overwrite))
        if fail_fast and files[-1].status != "written":
            break
    return files


def find_scan(lookup: ScanLookup, requested: str, project_root: Path) -> "Scan":
    """The scan to report on; ``scan_not_found`` when there is none."""
    scan = lookup.latest(project_root) if requested == LATEST else lookup.get(requested)
    if scan is None:
        raise UsageError(
            "no stored scan matches --scan", code="scan_not_found", hint="run codekavach scan first"
        )
    return scan


def _render_table(scan: "Scan", findings: int, files: Sequence[RenderedFile]) -> Any:
    def render(console: Console) -> None:
        started = scan.started_at.strftime("%Y-%m-%d %H:%M UTC")
        console.print(f"scan {scan.id} ({started}, {findings} findings)", markup=False)
        table = Table(show_header=True, header_style="bold", box=TABLE_BOX, pad_edge=False)
        for column in ("format", "path", "size"):
            table.add_column(column, overflow="fold")
        for item in files:
            size = (
                human_size(item.size_bytes)
                if item.size_bytes is not None
                else f"failed ({item.reason_code})"
            )
            table.add_row(item.format, display_path(item.path), size)
        console.print(table)

    return render


def report_command(  # noqa: PLR0917 - Typer maps each parameter to one option
    ctx: typer.Context,
    target: Annotated[
        str, typer.Argument(help="Project directory whose stored scans are used.")
    ] = ".",
    scan: Annotated[str, typer.Option("--scan", help="Scan id, or latest.")] = LATEST,
    formats: Annotated[
        list[str] | None,
        typer.Option("--format", help="Report format(s); repeatable or comma-separated."),
    ] = None,
    output_dir: Annotated[
        Path | None, typer.Option("--output-dir", help="Directory for the report files.")
    ] = None,
    name: Annotated[str, typer.Option("--name", help="File name without extension.")] = "report",
    overwrite: Annotated[
        bool, typer.Option("--overwrite/--no-overwrite", help="Replace existing files.")
    ] = True,
    fail_fast: Annotated[
        bool, typer.Option("--fail-fast", help="Stop at the first format that fails.")
    ] = False,
) -> None:
    """Render the report of a stored scan."""
    project = Path(target)
    if not project.is_dir():
        raise UsageError(f"project directory does not exist: {target}", code="target_not_found")
    cli_ctx = with_target(ctx, project)
    out = get_output(ctx)
    loaded = cli_ctx.loaded
    settings = loaded.settings
    requested = parse_formats(formats or [item.value for item in settings.reporting.formats])
    build_document = load_backend(
        "codekavach.report.model", "build_report_document", feature="report content", epic="E30"
    )
    registry: RendererRegistry = load_backend(
        "codekavach.report.render", "renderer_registry", feature="report renderers", epic="E31"
    )()
    check_formats(requested, registry)

    from codekavach.config.paths import resolve_state_dir  # noqa: PLC0415

    state_dir = resolve_state_dir(loaded.project_root, settings.project.state_dir)
    destination = check_output_dir(
        loaded.resolve_path(output_dir or settings.reporting.output_dir), state_dir
    )
    lookup: ScanLookup = load_backend(
        "codekavach.core.store.repositories", "open_scan_lookup", feature="stored scans", epic="E04"
    )(state_dir)
    stored = find_scan(lookup, scan, loaded.project_root)
    findings = lookup.findings(str(stored.id))
    if findings is None:
        raise UsageError(
            "the scan has no restored findings (it did not finish)",
            code="scan_incomplete",
            hint="run codekavach scan again",
        )
    document = build_document(stored, findings)
    files = render_all(
        registry,
        requested,
        document,
        output_dir=destination,
        stem=name,
        overwrite=overwrite,
        fail_fast=fail_fast,
    )
    out.result(
        {"scan_id": str(stored.id), "files": [item.to_json() for item in files]},
        human=_render_table(stored, len(findings), files),
    )
    failed = [item.format for item in files if item.status != "written"]
    if failed:
        raise InternalError(
            f"report format(s) not written: {', '.join(failed)}",
            code="render_failed",
            hint=DOCTOR_HINT,
        )
