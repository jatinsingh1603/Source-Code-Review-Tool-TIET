"""Report generation for server scans through the installed renderers.

Owning epic: E32.

Renderers are discovered through the ``codekavach.renderers`` entry point (``renderer_registry``),
so formats added by other packages appear without a change here. A report is rendered from the
scan's stored ``Scan`` record, the findings with their current triage status and the ledger
summary; a cached file is re-rendered when triage changed after it was written.
"""

import functools
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from codekavach.core.log import get_logger

if TYPE_CHECKING:
    from codekavach.config import Settings
    from codekavach.core.models.finding import Finding

_log = get_logger("codekavach.server.reports")

MEDIA_TYPES: Final = {
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "sarif": "application/sarif+json",
    "json": "application/json",
    "csv": "text/csv; charset=utf-8",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "md": "text/markdown; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "markdown": "text/markdown; charset=utf-8",
    "compliance": "text/html; charset=utf-8",
    "manifest": "application/json",
}
LABELS: Final = {
    "html": "HTML report",
    "pdf": "PDF report",
    "sarif": "SARIF 2.1.0",
    "json": "JSON export",
    "csv": "CSV export",
    "xlsx": "Excel workbook",
    "md": "Markdown report",
    "docx": "Word document",
    "markdown": "Markdown report",
    "compliance": "Compliance annex",
    "manifest": "Integrity manifest",
}
#: Formats that only repeat another one under a second name (``markdown`` is ``md``).
ALIASES: Final = {"markdown": "md"}


@functools.cache
def _installed_registry() -> Any:
    """The renderer registry without settings, built once per process.

    Building it reads the installed entry points, which takes about a second and serialises
    concurrent requests; what is installed does not change while the server runs.
    """
    from codekavach.report.render.base import renderer_registry  # noqa: PLC0415

    return renderer_registry(None)


def _registry(settings: "Settings | None") -> Any:
    if settings is None:
        return _installed_registry()
    from codekavach.report.render.base import renderer_registry  # noqa: PLC0415

    return renderer_registry(settings)


def available_formats(settings: "Settings | None" = None) -> list[str]:
    """The report formats the installed renderers provide."""
    try:
        return list(_registry(settings).names())
    except Exception as error:  # noqa: BLE001 - no renderer is a reportable state, not a crash
        _log.warning("server_renderers_unavailable", error_type=type(error).__name__)
        return []


def extension_of(fmt: str, settings: "Settings | None" = None) -> str:
    """The file extension of ``fmt`` (from the renderer when it says)."""
    try:
        value = getattr(_registry(settings).get(fmt), "extension", fmt)
        return str(value).lstrip(".") or fmt
    except Exception:  # noqa: BLE001 - fall back to the format name
        return fmt


def report_file(out_dir: Path, fmt: str, stem: str = "report") -> Path:
    """Where the rendered ``fmt`` is kept: one file per format, never shared between two."""
    return out_dir / f"{stem}.{extension_of(fmt)}"


def apply_statuses(findings: "Sequence[Finding]", statuses: dict[str, str]) -> "list[Finding]":
    """``findings`` with the server's triage status applied."""
    from codekavach.core.models.enums import FindingStatus  # noqa: PLC0415

    known = {item.value for item in FindingStatus}
    updated = []
    for finding in findings:
        status = statuses.get(str(finding.id))
        if status in known and status != finding.status.value:
            updated.append(finding.model_copy(update={"status": FindingStatus(status)}))
        else:
            updated.append(finding)
    return updated


def scan_label(server_scan_id: str) -> str | None:
    """The id the dashboard shows for a server scan (``scn_6b14be...`` is ``SCN-6B14BE``)."""
    if not server_scan_id.startswith("scn_"):
        return None
    return "SCN-" + server_scan_id.removeprefix("scn_")[:6].upper()


def render(
    fmt: str,
    *,
    scan_json: Path,
    state_dir: Path,
    findings: "Sequence[Finding]",
    settings: "Settings",
    out_dir: Path,
    zero_leak: dict[str, Any] | None,
    stem: str,
    project_name: str | None = None,
) -> Path:
    """Render ``fmt`` into ``out_dir`` and return the file.

    Raises:
        KeyError: no installed renderer provides ``fmt``.
        Exception: the renderer failed (for example the PDF back end is missing).
    """
    from codekavach.core.models.scan import Scan  # noqa: PLC0415
    from codekavach.report.model.build import (  # noqa: PLC0415
        build_report_document,
        summarise_ledger,
    )
    from codekavach.report.model.document import ZeroLeak  # noqa: PLC0415
    from codekavach.report.render.base import renderer_registry  # noqa: PLC0415

    renderer = renderer_registry(settings).get(fmt)
    scan = Scan.model_validate(json.loads(scan_json.read_text(encoding="utf-8")))
    leak = None
    if zero_leak:
        leak = ZeroLeak(
            checked=bool(zero_leak.get("checked")),
            terms_checked=int(zero_leak.get("checked") or 0),
            occurrences=int(zero_leak.get("occurrences") or 0),
        )
    document = build_report_document(
        scan, list(findings), settings, summarise_ledger(state_dir, str(scan.id), settings,
                                                         zero_leak=leak),
        project_name=project_name, scan_reference=scan_label(scan_json.parent.name),
    )  # fmt: skip
    out_dir.mkdir(parents=True, exist_ok=True)
    extension = str(getattr(renderer, "extension", fmt)).lstrip(".") or fmt
    target = out_dir / f"{stem}.{extension}"
    written = renderer.render(document, target)
    return Path(written)


def render_manifest(
    *,
    scan_json: Path,
    state_dir: Path,
    findings: "Sequence[Finding]",
    settings: "Settings",
    out_dir: Path,
    files: "Sequence[Path]",
    project_name: str | None = None,
) -> Path:
    """Write ``manifest.json`` (SHA-256 and size of every rendered report file) into ``out_dir``."""
    from codekavach.core.models.scan import Scan  # noqa: PLC0415
    from codekavach.report.model.build import (  # noqa: PLC0415
        build_report_document,
        summarise_ledger,
    )
    from codekavach.report.render.bundle import write_manifest  # noqa: PLC0415

    scan = Scan.model_validate(json.loads(scan_json.read_text(encoding="utf-8")))
    document = build_report_document(
        scan,
        list(findings),
        settings,
        summarise_ledger(state_dir, str(scan.id), settings),
        project_name=project_name,
        scan_reference=scan_label(scan_json.parent.name),
    )
    manifest, _sums = write_manifest(files, out_dir, doc=document)
    return manifest


def render_delta(
    *,
    current: tuple[Path, Path, "Sequence[Finding]"],
    baseline: tuple[Path, Path, "Sequence[Finding]"],
    settings: "Settings",
    out: Path,
    project_name: str | None = None,
) -> Path:
    """Write the retest delta (new, regressed, still open, fixed) of two scans as HTML.

    ``current`` and ``baseline`` are each ``(scan_json, state_dir, findings)``; findings are
    matched by fingerprint.
    """
    from codekavach.core.models.scan import Scan  # noqa: PLC0415
    from codekavach.report.model.build import (  # noqa: PLC0415
        build_report_document,
        summarise_ledger,
    )
    from codekavach.report.render.bundle import build_delta, render_delta_html  # noqa: PLC0415

    def document(scan_json: Path, state_dir: Path, findings: "Sequence[Finding]") -> Any:
        scan = Scan.model_validate(json.loads(scan_json.read_text(encoding="utf-8")))
        return build_report_document(
            scan,
            list(findings),
            settings,
            summarise_ledger(state_dir, str(scan.id), settings),
            project_name=project_name,
            scan_reference=scan_label(scan_json.parent.name),
        )

    now = document(*current)
    before = document(*baseline)
    delta = build_delta(now, before)
    # Name each scan by the id the dashboard shows, with the pipeline id beside it.
    labels = {
        "baseline_scan": (before.scan_reference, delta.baseline_scan),
        "current_scan": (now.scan_reference, delta.current_scan),
    }
    delta = delta.model_copy(
        update={key: f"{label} ({core})" for key, (label, core) in labels.items() if label}
    )
    return render_delta_html(delta, now, out)


def is_fresh(path: Path, changed_at: datetime | None) -> bool:
    """Whether a rendered file is newer than the last triage change."""
    if not path.is_file():
        return False
    if changed_at is None:
        return True
    return path.stat().st_mtime >= changed_at.timestamp()
