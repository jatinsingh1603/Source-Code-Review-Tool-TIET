"""Routes ``/scans``: status, live events, cancel, findings, privacy, ledger, reports, sync.

Owning epic: E32.

A scan row is created by ``POST /projects/{id}/scans`` and run by the job runner. ``/events`` is a
server-sent event stream that resumes from ``Last-Event-ID``. ``/privacy`` and ``/ledger`` read the
scan's egress ledger; the payload text and the original slice of ``/ledger/{seq}`` need
``privacy:read_original`` (auditor, admin) and every such read is audited with the entry number
only. ``/reports/{fmt}`` renders through the installed renderers and re-renders after triage.
"""

import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.core.log import get_logger
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
from codekavach.server.finding_query import FindingFilters, list_findings
from codekavach.server.rbac import Permission
from codekavach.server.reports import (
    ALIASES,
    LABELS,
    MEDIA_TYPES,
    apply_statuses,
    available_formats,
    is_fresh,
    render,
    render_delta,
    render_manifest,
    report_file,
)
from codekavach.server.results import (
    SEVERITY_ORDER,
    ScanPaths,
    ScanResults,
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
_log = get_logger("codekavach.server.scans")
ReportDep = Depends(require(Permission.report_read))
SyncDep = Depends(require(Permission.sync))
LEVELS: Final = ("L0", "L1", "L2", "L3", "L4")
# Providers that run on this machine: a scan with one of them has a meaningful time estimate.
LOCAL_PROVIDERS: Final = frozenset({"mock", "replay", "none", ""})
_settings_cache: dict[str, Any] = {}
_cache_lock = threading.Lock()


_record_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _scan_record(row: ScanRow) -> dict[str, Any]:
    """The core scan record (``scan.json``) of a finished scan; ``{}`` when absent."""
    if not row.workspace:
        return {}
    path = ScanPaths(Path(row.workspace)).scan_json
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    with _cache_lock:
        cached = _record_cache.get(row.id)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    try:
        import json  # noqa: PLC0415

        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    record = record if isinstance(record, dict) else {}
    with _cache_lock:
        _record_cache[row.id] = (mtime, record)
    return record


def scan_engines(row: ScanRow) -> list[dict[str, Any]]:
    """The analysers the pipeline ran (its ``analyse-*`` stages) and how each ended."""
    stages = _scan_record(row).get("stages") or []
    return [
        {"id": str(stage["name"]).removeprefix("analyse-"), "status": stage.get("status")}
        for stage in stages
        if isinstance(stage, dict) and str(stage.get("name", "")).startswith("analyse-")
    ]


def eta_seconds(row: ScanRow) -> int | None:
    """Seconds left, from the elapsed time and the progress of a running scan."""
    started = as_utc(row.started_at)
    if row.status != "running" or started is None or row.progress < 5:
        return None
    if row.send and row.provider not in LOCAL_PROVIDERS:
        # A remote model answers in seconds to minutes per request: a figure extrapolated from
        # the local stages would be wrong by an order of magnitude, so none is given.
        return None
    elapsed = (utcnow() - started).total_seconds()
    return max(0, int(elapsed * (100 - row.progress) / row.progress))


def scan_json(row: ScanRow, project: Project | None = None) -> dict[str, Any]:
    """The JSON of a scan row (``project`` adds the mode and ref of its source)."""
    counts = {name: int((row.counts or {}).get(name, 0)) for name in SEVERITY_ORDER}
    privacy = row.privacy or {}
    record = _scan_record(row)
    ref = (project.source_ref if project is not None else None) or record.get("git_branch")
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
        "mode": "branch" if project is not None and project.source_type == "git" else "full",
        "ref": ref,
        "commit": record.get("git_commit"),
        "payloads": privacy.get("payloads") if privacy else None,
        "engines": scan_engines(row),
        "eta_seconds": eta_seconds(row),
        "duration_seconds": (
            int((as_utc(row.finished_at) - as_utc(row.started_at)).total_seconds())  # type: ignore[operator]
            if row.finished_at is not None and row.started_at is not None
            else None
        ),
        "privacy_summary": {
            key: privacy.get(key)
            for key in (
                "payloads", "blocked", "chain_ok", "zero_leak", "tokens_sent", "bytes_sent",
                "lines_sent", "privacy_score",
            )
        }
        if privacy
        else None,
    }  # fmt: skip


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
    level = body.privacy_level or str(defaults.get("default_privacy_level") or "L3")
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
    if body.review_limit is not None:  # read by the job (jobs.scan._options)
        (Path(str(row.workspace)) / "scan-options.json").write_text(
            json.dumps({"review_limit": body.review_limit}), encoding="utf-8"
        )
    session.add(row)
    session.commit()
    audit.record(state.db, actor=principal.username, action="scan.create", resource=scan_id,
                 client=client, detail={"project": project.id, "provider": provider,
                                        "level": level, "send": send})  # fmt: skip
    state.hub.log(scan_id).append(
        "log", {"level": "info", "message": f"Scan queued for {project.name}"}
    )
    state.runner.submit(scan_id)
    return scan_json(row, project)


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
    projects = {project.id: project for project in session.scalars(select(Project))}
    return [scan_json(row, projects.get(row.project_id)) for row in session.scalars(query)]


@router.get("/scans/{scan_id}", dependencies=[ReadDep])
def get_scan(scan_id: str, session: SessionDep) -> dict[str, Any]:
    """One scan."""
    row = get_scan_row(session, scan_id)
    project = session.get(Project, row.project_id)
    data = scan_json(row, project)
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
    return scan_json(row, session.get(Project, row.project_id))


@router.get("/scans/{scan_id}/findings")
def scan_findings(
    scan_id: str,
    response: Response,
    state: StateDep,
    session: SessionDep,
    severity: str | None = None,
    status: str | None = None,
    cwe: str | None = None,
    q: str | None = None,
    engine: str | None = None,
    path: str | None = None,
    language: str | None = None,
    verdict: str | None = None,
    level: str | None = None,
    owasp: str | None = None,
    assignee: str | None = None,
    baseline_state: str | None = None,
    baseline: str | None = None,
    offset: int = 0,
    limit: int | None = None,
    principal: Any = ReadDep,
) -> list[dict[str, Any]]:
    """The findings of a scan, most severe first, filtered; the total is in ``X-Total-Count``."""
    get_scan_row(session, scan_id)
    filters = FindingFilters(
        severity=severity, status=status, cwe=cwe, q=q, engine=engine, path=path,
        language=language, verdict=verdict, level=level, owasp=owasp, assignee=assignee,
        baseline_state=baseline_state,
    )  # fmt: skip
    page = list_findings(session, [scan_id], filters, settings=state.get_settings(),
                         offset=offset, limit=limit, baseline=baseline,
                         me=principal.username)  # fmt: skip
    response.headers["X-Total-Count"] = str(page["total"])
    response.headers["X-Offset"] = str(page["offset"])
    response.headers["X-Limit"] = str(page["limit"])
    items: list[dict[str, Any]] = page["items"]
    return items


def privacy_extras(state: ServerState, row: ScanRow) -> dict[str, Any]:
    """Byte and line figures for a scan stored before they were recorded."""
    data = dict(row.privacy or {})
    if "bytes_sent" in data:
        return {}
    results = scan_results(state, row)
    extra = {"bytes_sent": 0, "lines_sent": 0, "bytes_recorded": 0, "lines_recorded": 0}
    for record in results.records():
        outcome = str(record.outcome.value)
        size = results.payload_size(record.payload_hash) or (0, 0)
        if outcome == "sent":
            extra["bytes_sent"] += size[0]
            extra["lines_sent"] += size[1]
        elif outcome == "not_sent_dry_run":
            extra["bytes_recorded"] += size[0]
            extra["lines_recorded"] += size[1]
    row.privacy = {**data, **extra}
    return extra


@router.get("/scans/{scan_id}/privacy", dependencies=[LedgerDep])
def scan_privacy(scan_id: str, state: StateDep, session: SessionDep) -> dict[str, Any]:
    """The privacy summary of a completed scan."""
    row = get_scan_row(session, scan_id)
    _completed(row)
    privacy_extras(state, row)
    data = dict(row.privacy or {})
    data.setdefault("level", row.privacy_level)
    data["provider"] = data.get("provider") or row.provider
    data["model"] = row.model or data.get("model")
    data["send"] = row.send
    data["repo_bytes"] = repo_bytes(row)
    data["lines_total"] = row.lines
    data["score_parts"] = [
        {"label": item.get("name"), "value": item.get("value"), "kind": item.get("kind")}
        for item in data.get("score_components") or []
        if isinstance(item, dict)
    ]
    return data


def repo_bytes(row: ScanRow) -> int | None:
    """Total size of the scanned copy of the code (the state directory excluded)."""
    if not row.workspace:
        return None
    source = ScanPaths(Path(row.workspace)).source
    if not source.is_dir():
        return None
    total = 0
    for item in source.rglob("*"):
        if ".codekavach" in item.parts or ".git" in item.parts:
            continue
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def _ledger_filter(
    entries: list[dict[str, Any]],
    q: str | None,
    outcome: str | None,
    provider: str | None,
    finding_id: str | None,
) -> list[dict[str, Any]]:
    wanted = {item.strip() for item in (outcome or "").split(",") if item.strip()}
    needle = (q or "").strip().lower()
    found = []
    for entry in entries:
        if wanted and entry["outcome"] not in wanted:
            continue
        if provider and entry["provider"] != provider:
            continue
        if finding_id and entry["finding_id"] != finding_id:
            continue
        if needle:
            haystack = " ".join(
                str(entry.get(key) or "")
                for key in ("seq", "payload_hash", "entry_hash", "candidate_id", "finding_id",
                            "provider", "model", "task", "outcome", "block_code")
            ).lower()  # fmt: skip
            if needle not in haystack:
                continue
        found.append(entry)
    return found


@router.get("/scans/{scan_id}/ledger")
def scan_ledger(
    scan_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    q: str | None = None,
    outcome: str | None = None,
    provider: str | None = None,
    finding_id: str | None = None,
    offset: int = 0,
    limit: int | None = None,
    format: str = "json",  # noqa: A002 - the documented query parameter
    principal: Any = LedgerDep,
) -> Any:
    """The egress ledger entries (metadata and hashes, no payload text), paged and filtered.

    ``format=jsonl`` downloads the matching entries as JSON Lines, one record per line.
    """
    row = get_scan_row(session, scan_id)
    results = scan_results(state, row)
    entries = _ledger_filter(
        results.ledger_rows(finding_map(session, scan_id)), q, outcome, provider, finding_id
    )
    if format == "jsonl":
        audit.record(state.db, actor=principal.username, action="privacy.export_ledger",
                     resource=scan_id, client=client_of(request),
                     detail={"entries": len(entries)})  # fmt: skip
        body = "".join(json.dumps(entry, default=str, sort_keys=True) + "\n" for entry in entries)
        return Response(
            body,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": f'attachment; filename="ledger-{scan_id}.jsonl"'},
        )
    if format != "json":
        raise ApiError(400, "invalid_format", "format is json or jsonl")
    total = len(entries)
    start = max(0, offset)
    size = max(total, 1) if limit is None else max(1, min(limit, 1000))
    page = entries[start : start + size]
    return {
        "scan_id": scan_id,
        "count": len(page),
        "total": total,
        "offset": start,
        "limit": size,
        # A response record names its request's payload; count each payload once.
        "bytes_total": sum(
            int(entry.get("bytes") or 0) for entry in entries if entry.get("ref_seq") is None
        ),
        "entries": page,
    }


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


@router.get("/scans/{scan_id}/ledger/{seq}/preview")
def scan_ledger_preview(
    scan_id: str,
    seq: int,
    level: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = OriginalDep,
) -> dict[str, Any]:
    """The same finding's payload as another scan of the project prepared it at ``level``.

    Nothing is prepared or sent here: the payload is read from the ledger of a completed scan of
    the same project at that level, matched by the candidate's fingerprint. 404 when no such scan
    covered the finding, so the page can say which scan to run.
    """
    if level not in {"L1", "L2", "L3", "L4"}:
        raise ApiError(400, "invalid_level", "level must be L1, L2, L3 or L4")
    row = get_scan_row(session, scan_id)
    fingerprint = scan_results(state, row).fingerprint_of(seq)
    if fingerprint is None:
        raise not_found("ledger entry")
    others = session.scalars(
        select(ScanRow)
        .where(
            ScanRow.project_id == row.project_id,
            ScanRow.status == "completed",
            ScanRow.privacy_level == level,
            ScanRow.id != row.id,
        )
        .order_by(ScanRow.finished_at.desc())
    ).all()
    for other in others:
        results = scan_results(state, other)
        other_seq = results.seq_of_fingerprint(fingerprint)
        if other_seq is None:
            continue
        detail = results.ledger_entry_detail(other_seq, finding_map(session, other.id))
        if detail is None:
            continue
        audit.record(state.db, actor=principal.username, action="privacy.read_original",
                     resource=f"{other.id}#{other_seq}", client=client_of(request),
                     outcome="allowed", detail={"preview_for": f"{scan_id}#{seq}"})  # fmt: skip
        return {**detail, "source_scan_id": other.id, "source_seq": other_seq}
    message = f"no completed scan of this project at {level} prepared this finding"
    raise ApiError(404, "no_scan_at_level", message)


def terms_file_for(state: ServerState, session: Session, row: ScanRow) -> Path | None:
    """The listed-terms file the scan's zero-leak check uses (as the scan job chooses it)."""
    project = session.get(Project, row.project_id)
    if project is not None and project.source_type == "sample" and state.config.sample_dir:
        candidate = state.config.sample_dir / "ground-truth" / "terms.txt"
        return candidate if candidate.is_file() else None
    if row.workspace:
        candidate = ScanPaths(Path(row.workspace)).source / ".codekavach-terms.txt"
        return candidate if candidate.is_file() else None
    return None


def verification(state: ServerState, session: Session, row: ScanRow) -> dict[str, Any]:
    """The full ledger verification of a scan: chain, payload hashes, listed terms."""
    results = scan_results(state, row)
    steps = results.verify(terms_file_for(state, session, row))
    chain_ok, entries, reason = results.chain()
    data = {step.name: step.data if isinstance(step.data, dict) else {} for step in steps}
    records = results.records()
    sent = [record for record in records if str(record.outcome.value) == "sent"]
    payloads = data.get("payloads", {})
    terms = data.get("terms", {})
    return {
        "scan_id": row.id,
        "ok": all(step.ok for step in steps if step.name in {"chain", "payloads"}) and chain_ok,
        "chain_ok": chain_ok,
        "entries": entries,
        "reason": reason,
        "first_bad_seq": (data.get("chain") or {}).get("first_bad_seq"),
        "hashes_ok": int(payloads.get("checked", 0)) - len(payloads.get("mismatched", [])),
        "hashes_mismatched": len(payloads.get("mismatched", [])),
        "payloads_missing": len(payloads.get("missing", [])),
        "blocked": sum(1 for record in records if str(record.outcome.value) == "blocked"),
        # Payloads are stored by hash, so two identical payloads are one file and one check.
        "payloads_sent": len(sent),
        "payloads_distinct": len({record.payload_hash for record in sent}),
        "terms_checked": int(terms.get("checked", 0)),
        "terms_found": len(terms.get("hits", [])),
        "head_hash": records[-1].entry_hash if records else None,
        "message": "; ".join(str(step.summary or step.message) for step in steps),
        "steps": [
            {"name": step.name, "ok": step.ok, "summary": step.summary or step.message}
            for step in steps
        ],
        "verified_at": utcnow(),
    }


@router.post("/scans/{scan_id}/ledger/verify")
def verify_ledger(
    scan_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = LedgerDep,
) -> dict[str, Any]:
    """Walk the hash chain, re-hash every stored payload and search for the listed terms now."""
    row = get_scan_row(session, scan_id)
    result = verification(state, session, row)
    audit.record(state.db, actor=principal.username, action="privacy.verify_ledger",
                 resource=scan_id, client=client_of(request))  # fmt: skip
    return result


@router.get("/scans/{scan_id}/ledger-verification")
def verification_report(
    scan_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    format: str = "json",  # noqa: A002 - the documented query parameter
    principal: Any = LedgerDep,
) -> Response:
    """Download the verification report (``json`` or ``txt``)."""
    row = get_scan_row(session, scan_id)
    result = verification(state, session, row)
    audit.record(state.db, actor=principal.username, action="privacy.verification_report",
                 resource=scan_id, client=client_of(request))  # fmt: skip
    if format == "txt":
        lines = [
            f"CodeKavach egress ledger verification for scan {scan_id}",
            f"Verified at {result['verified_at'].isoformat()}",
            f"Result: {'PASS' if result['ok'] else 'FAIL'}",
            f"Chain: {'intact' if result['chain_ok'] else 'broken'} over {result['entries']} "
            f"entries; head {result['head_hash'] or '-'}",
            f"Payload hashes: {result['hashes_ok']} match, {result['hashes_mismatched']} "
            f"mismatch, {result['payloads_missing']} missing ({result['payloads_sent']} payloads "
            f"sent, {result['payloads_distinct']} distinct; identical payloads are stored and "
            "checked once)",
            f"Blocked by the egress guard: {result['blocked']}",
            f"Listed terms: {result['terms_checked']} checked, {result['terms_found']} found "
            "(verbatim search only)",
            "",
            *[f"[{'ok' if step['ok'] else 'FAIL'}] {step['summary']}" for step in result["steps"]],
        ]
        media, body, suffix = "text/plain; charset=utf-8", "\n".join(lines) + "\n", "txt"
    elif format == "json":
        media = "application/json"
        body = json.dumps(result, default=str, indent=2, sort_keys=True) + "\n"
        suffix = "json"
    else:
        raise ApiError(400, "invalid_format", "format is json or txt")
    return Response(
        body,
        media_type=media,
        headers={"Content-Disposition":
                 f'attachment; filename="ledger-verification-{scan_id}.{suffix}"'},
    )  # fmt: skip


@router.get("/scans/{scan_id}/privacy/attestation.{fmt}")
def download_attestation(
    scan_id: str,
    fmt: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = ReportDep,
) -> Response:
    """The structured privacy attestation as JSON, or the PDF report that carries it."""
    row = get_scan_row(session, scan_id)
    paths, core_id = _completed(row)
    if fmt == "pdf":
        return download_report(scan_id, "pdf", request, state, session, False, principal)
    if fmt != "json":
        raise ApiError(404, "format_unavailable", "the attestation is available as json or pdf")
    from codekavach.core.models.enums import PrivacyLevel  # noqa: PLC0415
    from codekavach.privacy.attestation import build_attestation  # noqa: PLC0415

    results = scan_results(state, row)
    settings = results.settings
    terms = terms_file_for(state, session, row)
    if terms is not None:
        privacy = settings.privacy.model_copy(update={"domain_terms_file": terms})
        settings = settings.model_copy(update={"privacy": privacy})
    try:
        attestation = build_attestation(
            paths.state_dir, core_id, settings, level=PrivacyLevel(row.privacy_level)
        )
    except Exception as error:  # noqa: BLE001 - reported as an API error, not a 500
        raise ApiError(503, "attestation_failed", "the attestation could not be built",
                       hint=type(error).__name__) from None  # fmt: skip
    records = results.records()
    levels: dict[str, int] = {}
    for record in records:
        if record.ref_seq is not None:
            continue  # a response record, not another request at that level
        levels[str(record.level.value)] = levels.get(str(record.level.value), 0) + 1
    privacy_extras(state, row)
    stored = row.privacy or {}
    body = {
        "attestation": attestation.to_api(),
        "scan_id": scan_id,
        "core_scan_id": core_id,
        "levels_used": levels,
        "bytes_sent": stored.get("bytes_sent"),
        "lines_sent": stored.get("lines_sent"),
        "ledger_head_hash": records[-1].entry_hash if records else None,
        "generated_at": utcnow(),
        "digest": attestation.digest(),
        "digest_algorithm": "sha256 over the canonical JSON of the attestation",
        "signature": None,
        "signature_note": "the server holds no signing key; verify with the digest and the "
        "ledger head hash",
    }
    audit.record(state.db, actor=principal.username, action="privacy.attestation",
                 resource=scan_id, client=client_of(request))  # fmt: skip
    return Response(
        json.dumps(body, default=str, indent=2, sort_keys=True) + "\n",
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="attestation-{scan_id}.json"'},
    )


@router.get("/scans/{scan_id}/reports", dependencies=[ReportDep])
def list_reports(scan_id: str, state: StateDep, session: SessionDep) -> dict[str, Any]:
    """The report formats that can be downloaded for this scan, and the integrity manifest."""
    row = get_scan_row(session, scan_id)
    formats = [fmt for fmt in available_formats() if fmt not in ALIASES]
    reports = ScanPaths(Path(row.workspace)).reports if row.workspace else None

    def entry(fmt: str, path: Path | None) -> dict[str, Any]:
        done = path is not None and path.is_file()
        digest = None
        if done and path is not None and fmt == "manifest":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "format": fmt,
            "label": LABELS.get(fmt, fmt.upper()),
            "media_type": MEDIA_TYPES.get(fmt, "application/octet-stream"),
            "available": True,
            "reason": None,
            "rendered": done,
            "size": path.stat().st_size if done and path is not None else None,
            "sha256": digest,
            "url": f"/api/v1/scans/{scan_id}/reports/{fmt}",
        }

    items = [entry(fmt, report_file(reports, fmt) if reports else None) for fmt in formats]
    if formats:
        items.append(entry("manifest", reports / MANIFEST if reports else None))
    return {"scan_id": scan_id, "ready": row.status == "completed", "formats": items}


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
    formats = available_formats()
    if fmt == "manifest" and formats:
        target = _manifest(state, session, row, paths, core_id, formats)
        return _report_response(request, state, session, row, principal, fmt, target, inline)
    if fmt not in formats:
        raise ApiError(404, "format_unavailable", f"no renderer for the format {fmt}")
    results = scan_results(state, row)
    target = report_file(paths.reports, fmt)
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
                project_name=_project_name(session, row),
            )
        except Exception as error:  # noqa: BLE001 - reported as an API error, not a 500
            raise ApiError(
                503, "report_failed", f"the {fmt} report could not be rendered",
                hint=type(error).__name__,
            ) from None  # fmt: skip
    return _report_response(request, state, session, row, principal, fmt, target, inline)


MANIFEST: Final = "manifest.json"


def _project_name(session: Session, row: ScanRow) -> str | None:
    project = session.get(Project, row.project_id)
    return project.name if project else None


def _manifest(
    state: ServerState,
    session: Session,
    row: ScanRow,
    paths: ScanPaths,
    core_id: str,
    formats: list[str],
) -> Path:
    """Render every missing or stale format, then hash them all into ``manifest.json``."""
    changed = as_utc(row.triage_updated_at)
    statuses = {
        item.id: item.status
        for item in session.scalars(select(FindingRow).where(FindingRow.scan_id == row.id))
    }
    results = scan_results(state, row)
    settings = state.report_settings(results.settings)
    findings = apply_statuses(read_findings(paths, core_id), statuses)
    name = _project_name(session, row)
    files: list[Path] = []
    for fmt in formats:
        if fmt in ALIASES:
            continue
        target = report_file(paths.reports, fmt)
        if not is_fresh(target, changed):
            leak = (row.privacy or {}).get("zero_leak")
            try:
                target = render(fmt, scan_json=paths.scan_json, state_dir=paths.state_dir,
                                findings=findings, settings=settings, out_dir=paths.reports,
                                zero_leak=leak, stem="report", project_name=name)  # fmt: skip
            except Exception as error:  # noqa: BLE001 - a format that cannot render is left out
                _log.warning("manifest_format_skipped", format=fmt, error_type=type(error).__name__)
                continue
        files.append(target)
    existing = paths.reports / MANIFEST
    if _manifest_current(existing, files, changed):
        # Same files, same bytes: the auditor's earlier download keeps matching its hash.
        return existing
    try:
        return render_manifest(scan_json=paths.scan_json, state_dir=paths.state_dir,
                               findings=findings, settings=settings, out_dir=paths.reports,
                               files=files, project_name=name)  # fmt: skip
    except Exception as error:  # noqa: BLE001 - reported as an API error, not a 500
        raise ApiError(503, "report_failed", "the integrity manifest could not be written",
                       hint=type(error).__name__) from None  # fmt: skip


def _manifest_current(manifest: Path, files: list[Path], changed: Any) -> bool:
    """Whether ``manifest`` lists exactly ``files`` and is newer than each and the triage."""
    if not manifest.is_file() or not is_fresh(manifest, changed):
        return False
    try:
        listed = {item["file"] for item in json.loads(manifest.read_text("utf-8"))["files"]}
    except (OSError, ValueError, KeyError, TypeError):
        return False
    written = manifest.stat().st_mtime
    return listed == {f.name for f in files} and all(f.stat().st_mtime <= written for f in files)


def _report_response(
    request: Request,
    state: ServerState,
    session: Session,
    row: ScanRow,
    principal: Any,
    fmt: str,
    target: Path,
    inline: bool,
) -> FileResponse:
    scan_id = row.id
    audit.record(state.db, actor=principal.username, action="report.download",
                 resource=f"{scan_id}.{fmt}", client=client_of(request))  # fmt: skip
    project = session.get(Project, row.project_id)
    base = re.sub(r"[^A-Za-z0-9]+", "-", project.name if project else "project").strip("-")
    # "report.compliance.html" keeps its "compliance.html" so it never shares a name with the HTML.
    suffix = target.name.split(".", 1)[1] if target.name.startswith("report.") else target.name
    filename = f"codekavach-{base.lower() or 'project'}-{scan_id}.{suffix}"
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


@router.get("/scans/{scan_id}/delta")
def download_delta(
    scan_id: str,
    baseline: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = ReportDep,
) -> FileResponse:
    """The retest delta of this scan against an earlier scan of the same project, as HTML."""
    row = get_scan_row(session, scan_id)
    base_row = get_scan_row(session, baseline)
    if base_row.id == row.id or base_row.project_id != row.project_id:
        raise ApiError(422, "baseline_invalid",
                       "the baseline must be another scan of the same project")  # fmt: skip
    paths, core_id = _completed(row)
    base_paths, base_core = _completed(base_row)

    def findings_of(item: ScanRow, item_paths: ScanPaths, item_core: str) -> list[Any]:
        statuses = {
            f.id: f.status
            for f in session.scalars(select(FindingRow).where(FindingRow.scan_id == item.id))
        }
        return apply_statuses(read_findings(item_paths, item_core), statuses)

    results = scan_results(state, row)
    target = paths.reports / f"delta-{base_row.id}.html"
    try:
        render_delta(
            current=(paths.scan_json, paths.state_dir, findings_of(row, paths, core_id)),
            baseline=(base_paths.scan_json, base_paths.state_dir,
                      findings_of(base_row, base_paths, base_core)),
            settings=state.report_settings(results.settings),
            out=target,
            project_name=_project_name(session, row),
        )  # fmt: skip
    except Exception as error:  # noqa: BLE001 - reported as an API error, not a 500
        raise ApiError(503, "report_failed", "the delta report could not be rendered",
                       hint=type(error).__name__) from None  # fmt: skip
    audit.record(state.db, actor=principal.username, action="report.download",
                 resource=f"{scan_id}.delta", client=client_of(request),
                 detail={"baseline": base_row.id})  # fmt: skip
    project = session.get(Project, row.project_id)
    base = re.sub(r"[^A-Za-z0-9]+", "-", project.name if project else "project").strip("-")
    return FileResponse(
        target,
        media_type="text/html; charset=utf-8",
        filename=f"codekavach-{base.lower() or 'project'}-{scan_id}.delta-{base_row.id}.html",
    )


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
    query = select(FindingRow).where(FindingRow.scan_id == scan_id)
    if body.finding_ids:
        query = query.where(FindingRow.id.in_(body.finding_ids))
    findings = list(session.scalars(query.order_by(FindingRow.severity_rank.desc())))
    if body.finding_ids and len(findings) != len(set(body.finding_ids)):
        raise ApiError(404, "finding_not_in_scan", "a finding id does not belong to this scan")
    result = sync_scan(
        findings,
        repo=body.repo,
        token_ref=body.token_ref,
        dry_run=body.dry_run,
        allowed_refs=state.config.github_token_refs,
    )
    audit.record(state.db, actor=principal.username, action="sync.github", resource=scan_id,
                 client=client_of(request),
                 detail={"repo": body.repo, "dry_run": body.dry_run,
                         "findings": len(findings),
                         "created": result.get("created", 0)})  # fmt: skip
    return result
