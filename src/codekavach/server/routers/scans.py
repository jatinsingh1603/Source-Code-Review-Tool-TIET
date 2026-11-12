"""Routes ``/scans``: status, live events, cancel, findings, privacy, ledger, reports, sync.

Owning epic: E32.

A scan row is created by ``POST /projects/{id}/scans`` and run by the job runner. ``/events`` is a
server-sent event stream that resumes from ``Last-Event-ID``. ``/privacy`` and ``/ledger`` read the
scan's egress ledger; the payload text and the original slice of ``/ledger/{seq}`` need
``privacy:read_original`` (auditor, admin) and every such read is audited with the entry number
only. ``/reports/{fmt}`` renders through the installed renderers and re-renders after triage.
"""

import re
import threading
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.server import audit
from codekavach.server.auth.dependencies import (
    Principal,
    SessionDep,
    StateDep,
    client_of,
    require,
)
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import FindingRow, Project, ScanRow, utcnow
from codekavach.server.errors import ApiError, not_found
from codekavach.server.events import stream
from codekavach.server.rbac import Permission
from codekavach.server.reports import (
    LABELS,
    MEDIA_TYPES,
    apply_statuses,
    available_formats,
    is_fresh,
    render,
)
from codekavach.server.results import (
    SEVERITY_ORDER,
    ScanPaths,
    ScanResults,
    finding_summary,
    load_scan_settings,
    read_findings,
)
from codekavach.server.schemas import GithubSyncBody, ScanCreate
from codekavach.server.state import ServerState, new_id

router = APIRouter(tags=["scans"])
ReadDep = Depends(require(Permission.read))
RunDep = Depends(require(Permission.scan_run))
LedgerDep = Depends(require(Permission.ledger_read))
OriginalDep = Depends(require(Permission.original_read))
ReportDep = Depends(require(Permission.report_read))
SyncDep = Depends(require(Permission.sync))
LEVELS: Final = ("L0", "L1", "L2", "L3", "L4")
_settings_cache: dict[str, Any] = {}
_cache_lock = threading.Lock()


def scan_json(row: ScanRow) -> dict[str, Any]:
    """The JSON of a scan row."""
    counts = {name: int((row.counts or {}).get(name, 0)) for name in SEVERITY_ORDER}
    return {
        "id": row.id,
        "project_id": row.project_id,
        "status": row.status,
        "stage": row.stage,
        "progress": row.progress,
        "created_at": as_utc(row.created_at),
        "started_at": as_utc(row.started_at),
        "finished_at": as_utc(row.finished_at),
        "privacy_level": row.privacy_level,
        "provider": row.provider,
        "model": row.model,
        "send": row.send,
        "rules": row.rules or [],
        "counts": counts,
        "findings_total": sum(counts.values()),
        "files": row.files,
        "lines": row.lines,
        "languages": row.languages or [],
        "error": row.error,
        "core_scan_id": row.core_scan_id,
        "privacy_summary": {
            key: (row.privacy or {}).get(key)
            for key in ("payloads", "blocked", "chain_ok", "zero_leak", "tokens_sent")
        }
        if row.privacy
        else None,
    }


def start_scan(
    state: ServerState,
    session: Session,
    project: Project,
    body: ScanCreate,
    principal: Principal,
    client: str,
) -> dict[str, Any]:
    """Create the scan row, commit it and queue the job."""
    defaults = state.get_settings()
    provider = body.provider or str(defaults.get("default_provider") or "mock")
    level = body.privacy_level or str(defaults.get("default_privacy_level") or "L2")
    if level not in LEVELS:
        raise ApiError(400, "invalid_level", f"unknown privacy level {level}")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", provider):
        raise ApiError(400, "invalid_provider", "the provider id is not valid")
    send = body.send if body.send is not None else bool(defaults.get("send_by_default", True))
    scan_id = new_id("scn")
    row = ScanRow(
        id=scan_id,
        project_id=project.id,
        status="queued",
        privacy_level=level,
        provider=provider,
        model=body.model or (defaults.get("default_model") if provider == defaults.get(
            "default_provider") else None),
        send=send,
        rules=list(body.rules or []),
        workspace=str(state.config.scans_dir / scan_id),
        created_by=principal.user_id,
    )  # fmt: skip
    Path(str(row.workspace)).mkdir(parents=True, exist_ok=True)
    session.add(row)
    session.commit()
    audit.record(state.db, actor=principal.username, action="scan.create", resource=scan_id,
                 client=client, detail={"project": project.id, "provider": provider,
                                        "level": level, "send": send})  # fmt: skip
    state.hub.log(scan_id).append(
        "log", {"level": "info", "message": f"Scan queued for {project.name}"}
    )
    state.runner.submit(scan_id)
    return scan_json(row)


def get_scan_row(session: Session, scan_id: str) -> ScanRow:
    """The row of ``scan_id``; 404 when unknown."""
    row = session.get(ScanRow, scan_id)
    if row is None:
        raise not_found("scan")
    return row


def _completed(row: ScanRow) -> tuple[ScanPaths, str]:
    if row.status != "completed" or not row.core_scan_id or not row.workspace:
        raise ApiError(409, "scan_not_completed", "the scan has not completed")
    return ScanPaths(Path(row.workspace)), row.core_scan_id


def scan_results(state: ServerState, row: ScanRow) -> ScanResults:
    """The results reader of a completed scan (settings cached per scan)."""
    paths, core_id = _completed(row)
    with _cache_lock:
        settings = _settings_cache.get(row.id)
    if settings is None:
        settings = load_scan_settings(paths, state.config.home_dir, state.passphrase_env)
        with _cache_lock:
            _settings_cache[row.id] = settings
    return ScanResults(paths, core_id, settings)


def finding_map(session: Session, scan_id: str) -> dict[str, str]:
    """Candidate id to finding id for one scan."""
    mapping: dict[str, str] = {}
    for row in session.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)):
        for candidate in (row.data or {}).get("provenance", {}).get("candidate_ids", []) or []:
            mapping[str(candidate)] = row.id
    return mapping


@router.get("/scans", dependencies=[ReadDep])
def list_scans(
    session: SessionDep, project_id: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    """Scans, newest first, optionally of one project."""
    query = select(ScanRow).order_by(ScanRow.created_at.desc()).limit(max(1, min(limit, 1000)))
    if project_id:
        query = query.where(ScanRow.project_id == project_id)
    return [scan_json(row) for row in session.scalars(query)]


@router.get("/scans/{scan_id}", dependencies=[ReadDep])
def get_scan(scan_id: str, session: SessionDep) -> dict[str, Any]:
    """One scan."""
    row = get_scan_row(session, scan_id)
    data = scan_json(row)
    project = session.get(Project, row.project_id)
    data["project_name"] = project.name if project else None
    return data


@router.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = Depends(require(Permission.project_write)),
) -> dict[str, Any]:
    """Delete a finished scan and its workspace."""
    import shutil  # noqa: PLC0415

    row = get_scan_row(session, scan_id)
    if row.status in {"queued", "running"}:
        raise ApiError(409, "scan_active", "cancel the scan before deleting it")
    if row.workspace:
        shutil.rmtree(row.workspace, ignore_errors=True)
    state.hub.forget(scan_id)
    session.delete(row)
    audit.record(state.db, actor=principal.username, action="scan.delete", resource=scan_id,
                 client=client_of(request))  # fmt: skip
    return {"ok": True}


@router.get("/scans/{scan_id}/events", dependencies=[ReadDep])
async def scan_events(scan_id: str, request: Request, state: StateDep) -> StreamingResponse:
    """Server-sent events: ``stage``, ``progress``, ``log``, ``finding``, ``done``."""
    with state.db.transaction() as session:
        get_scan_row(session, scan_id)
    header = request.headers.get("last-event-id") or request.query_params.get("last_event_id")
    last_id = int(header) if header and header.isdigit() else 0
    frames = stream(
        state.hub.log(scan_id), last_id=last_id, is_disconnected=request.is_disconnected
    )
    return StreamingResponse(
        frames,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.get("/scans/{scan_id}/log", dependencies=[ReadDep])
def scan_log(scan_id: str, state: StateDep, session: SessionDep) -> list[dict[str, Any]]:
    """Every event of the scan so far (the non-streaming form of ``/events``)."""
    get_scan_row(session, scan_id)
    return [
        {"id": event.id, "type": event.type, "data": event.data}
        for event in state.hub.log(scan_id).all()
    ]


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = RunDep,
) -> dict[str, Any]:
    """Cancel a queued or running scan."""
    row = get_scan_row(session, scan_id)
    if row.status not in {"queued", "running"}:
        raise ApiError(409, "scan_not_active", f"the scan is already {row.status}")
    if not state.runner.cancel(scan_id):
        row.status, row.finished_at = "cancelled", utcnow()
        state.hub.log(scan_id).append("done", {"status": "cancelled", "error": None})
    audit.record(state.db, actor=principal.username, action="scan.cancel", resource=scan_id,
                 client=client_of(request))  # fmt: skip
    session.refresh(row)
    return scan_json(row)


@router.get("/scans/{scan_id}/findings", dependencies=[ReadDep])
def scan_findings(
    scan_id: str,
    session: SessionDep,
    severity: str | None = None,
    status: str | None = None,
    cwe: str | None = None,
    q: str | None = None,
    engine: str | None = None,
    path: str | None = None,
) -> list[dict[str, Any]]:
    """The findings of a scan, most severe first, filtered."""
    get_scan_row(session, scan_id)
    query = select(FindingRow).where(FindingRow.scan_id == scan_id)
    if severity:
        query = query.where(FindingRow.severity.in_(severity.lower().split(",")))
    if status:
        query = query.where(FindingRow.status.in_(status.lower().split(",")))
    if cwe:
        number = re.sub(r"(?i)^cwe-", "", cwe.strip())
        query = query.where(FindingRow.cwe.contains(f"CWE-{number}"))
    if engine:
        query = query.where(FindingRow.engine == engine)
    if path:
        query = query.where(FindingRow.path.contains(path))
    if q:
        pattern = f"%{q.lower()}%"
        query = query.where(
            FindingRow.title.ilike(pattern)
            | FindingRow.path.ilike(pattern)
            | FindingRow.rule_id.ilike(pattern)
            | FindingRow.cwe.ilike(pattern)
        )
    query = query.order_by(FindingRow.severity_rank.desc(), FindingRow.path, FindingRow.line)
    return [finding_summary(row) for row in session.scalars(query)]


@router.get("/scans/{scan_id}/privacy", dependencies=[LedgerDep])
def scan_privacy(scan_id: str, session: SessionDep) -> dict[str, Any]:
    """The privacy summary of a completed scan."""
    row = get_scan_row(session, scan_id)
    _completed(row)
    data = dict(row.privacy or {})
    data.setdefault("level", row.privacy_level)
    data["provider"] = data.get("provider") or row.provider
    data["model"] = row.model or data.get("model")
    data["send"] = row.send
    return data


@router.get("/scans/{scan_id}/ledger", dependencies=[LedgerDep])
def scan_ledger(scan_id: str, state: StateDep, session: SessionDep) -> dict[str, Any]:
    """The egress ledger entries of the scan (metadata and hashes, no payload text)."""
    row = get_scan_row(session, scan_id)
    results = scan_results(state, row)
    entries = results.ledger_rows(finding_map(session, scan_id))
    return {"scan_id": scan_id, "count": len(entries), "entries": entries}


@router.get("/scans/{scan_id}/ledger/{seq}")
def scan_ledger_entry(
    scan_id: str,
    seq: int,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = OriginalDep,
) -> dict[str, Any]:
    """One ledger entry with the payload sent and the original code it was built from."""
    row = get_scan_row(session, scan_id)
    results = scan_results(state, row)
    detail = results.ledger_entry_detail(seq, finding_map(session, scan_id))
    candidate = (detail or {}).get("entry", {}).get("candidate_id")
    audit.record(state.db, actor=principal.username, action="privacy.read_original",
                 resource=f"{scan_id}#{seq}", client=client_of(request),
                 outcome="allowed" if detail else "not_found",
                 detail={"candidate_id": candidate})  # fmt: skip
    if detail is None:
        raise not_found("ledger entry")
    return detail


@router.post("/scans/{scan_id}/ledger/verify")
def verify_ledger(
    scan_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = LedgerDep,
) -> dict[str, Any]:
    """Walk the hash chain and re-hash every stored payload now."""
    row = get_scan_row(session, scan_id)
    results = scan_results(state, row)
    steps = results.verify(None)
    chain_ok, entries, reason = results.chain()
    audit.record(state.db, actor=principal.username, action="privacy.verify_ledger",
                 resource=scan_id, client=client_of(request))  # fmt: skip
    return {
        "ok": all(step.ok for step in steps if step.name in {"chain", "payloads"}) and chain_ok,
        "chain_ok": chain_ok,
        "entries": entries,
        "reason": reason,
        "first_bad_seq": next(
            (
                step.data.get("first_bad_seq")
                for step in steps
                if step.name == "chain" and not step.ok and isinstance(step.data, dict)
            ),
            None,
        ),
        "message": "; ".join(str(step.summary or step.message) for step in steps),
        "steps": [
            {"name": step.name, "ok": step.ok, "summary": step.summary or step.message}
            for step in steps
        ],
        "verified_at": utcnow(),
    }


@router.get("/scans/{scan_id}/reports", dependencies=[ReportDep])
def list_reports(scan_id: str, state: StateDep, session: SessionDep) -> dict[str, Any]:
    """The report formats that can be downloaded for this scan."""
    row = get_scan_row(session, scan_id)
    formats = available_formats()
    rendered = {}
    if row.workspace:
        reports = ScanPaths(Path(row.workspace)).reports
        if reports.is_dir():
            rendered = {item.suffix.lstrip("."): item.stat().st_size for item in reports.iterdir()}
    return {
        "scan_id": scan_id,
        "ready": row.status == "completed",
        "formats": [
            {
                "format": fmt,
                "label": LABELS.get(fmt, fmt.upper()),
                "media_type": MEDIA_TYPES.get(fmt, "application/octet-stream"),
                "available": True,
                "reason": None,
                "rendered": fmt in rendered,
                "size": rendered.get(fmt),
                "url": f"/api/v1/scans/{scan_id}/reports/{fmt}",
            }
            for fmt in formats
        ],
    }


@router.get("/scans/{scan_id}/reports/{fmt}")
def download_report(
    scan_id: str,
    fmt: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    inline: bool = False,
    principal: Any = ReportDep,
) -> FileResponse:
    """Download the report in ``fmt`` (rendered now when missing or older than the triage)."""
    row = get_scan_row(session, scan_id)
    paths, core_id = _completed(row)
    if fmt not in available_formats():
        raise ApiError(404, "format_unavailable", f"no renderer for the format {fmt}")
    results = scan_results(state, row)
    extension = fmt
    existing = [item for item in paths.reports.glob("report.*") if item.suffix == f".{fmt}"]
    target = existing[0] if existing else paths.reports / f"report.{extension}"
    if not is_fresh(target, as_utc(row.triage_updated_at)):
        statuses = {
            item.id: item.status
            for item in session.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id))
        }
        try:
            target = render(
                fmt,
                scan_json=paths.scan_json,
                state_dir=paths.state_dir,
                findings=apply_statuses(read_findings(paths, core_id), statuses),
                settings=state.report_settings(results.settings),
                out_dir=paths.reports,
                zero_leak=(row.privacy or {}).get("zero_leak"),
                stem="report",
            )
        except Exception as error:  # noqa: BLE001 - reported as an API error, not a 500
            raise ApiError(
                503, "report_failed", f"the {fmt} report could not be rendered",
                hint=type(error).__name__,
            ) from None  # fmt: skip
    audit.record(state.db, actor=principal.username, action="report.download",
                 resource=f"{scan_id}.{fmt}", client=client_of(request))  # fmt: skip
    project = session.get(Project, row.project_id)
    base = re.sub(r"[^A-Za-z0-9]+", "-", project.name if project else "project").strip("-")
    filename = f"codekavach-{base.lower() or 'project'}-{scan_id}.{target.suffix.lstrip('.')}"
    response = FileResponse(
        target,
        media_type=MEDIA_TYPES.get(fmt, "application/octet-stream"),
        filename=filename,
        content_disposition_type="inline" if inline else "attachment",
    )
    if inline:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
            "font-src data:; frame-ancestors 'self'"
        )
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


@router.post("/scans/{scan_id}/sync/github")
def sync_github(
    scan_id: str,
    body: GithubSyncBody,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = SyncDep,
) -> dict[str, Any]:
    """Plan (dry run) or perform the GitHub issue sync of the scan's open findings."""
    from codekavach.server.github import sync_scan  # noqa: PLC0415

    row = get_scan_row(session, scan_id)
    _completed(row)
    findings = list(
        session.scalars(
            select(FindingRow)
            .where(FindingRow.scan_id == scan_id)
            .order_by(FindingRow.severity_rank.desc())
        )
    )
    result = sync_scan(findings, repo=body.repo, token_ref=body.token_ref, dry_run=body.dry_run)
    audit.record(state.db, actor=principal.username, action="sync.github", resource=scan_id,
                 client=client_of(request),
                 detail={"repo": body.repo, "dry_run": body.dry_run,
                         "created": result.get("created", 0)})  # fmt: skip
    return result
