"""Report generation for server scans through the installed renderers.

Owning epic: E32.

Renderers are discovered through the ``codekavach.renderers`` entry point (``renderer_registry``),
so formats added by other packages appear without a change here. A report is rendered from the
scan's stored ``Scan`` record, the findings with their current triage status and the ledger
summary; a cached file is re-rendered when triage changed after it was written.
"""

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
}


def available_formats(settings: "Settings | None" = None) -> list[str]:
    """The report formats the installed renderers provide."""
    try:
        from codekavach.report.render.base import renderer_registry  # noqa: PLC0415

        return list(renderer_registry(settings).names())
    except Exception as error:  # noqa: BLE001 - no renderer is a reportable state, not a crash
        _log.warning("server_renderers_unavailable", error_type=type(error).__name__)
        return []


def extension_of(fmt: str, settings: "Settings | None" = None) -> str:
    """The file extension of ``fmt`` (from the renderer when it says)."""
    try:
        from codekavach.report.render.base import renderer_registry  # noqa: PLC0415

        value = getattr(renderer_registry(settings).get(fmt), "extension", fmt)
        return str(value).lstrip(".") or fmt
    except Exception:  # noqa: BLE001 - fall back to the format name
        return fmt


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
                                                         zero_leak=leak)
    )  # fmt: skip
    out_dir.mkdir(parents=True, exist_ok=True)
    extension = str(getattr(renderer, "extension", fmt)).lstrip(".") or fmt
    target = out_dir / f"{stem}.{extension}"
    written = renderer.render(document, target)
    return Path(written)


def is_fresh(path: Path, changed_at: datetime | None) -> bool:
    """Whether a rendered file is newer than the last triage change."""
    if not path.is_file():
        return False
    if changed_at is None:
        return True
    return path.stat().st_mtime >= changed_at.timestamp()
