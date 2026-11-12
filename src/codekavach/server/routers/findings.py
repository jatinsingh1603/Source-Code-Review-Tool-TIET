"""Routes ``/findings``: the paged list, detail, triage (status, assignee, comment), history, views.

Owning epic: E32.

Triage is server state: the finding JSON the pipeline produced is kept as it was, and the status,
assignee and an append-only history of changes and comments are stored beside it. A change marks
the scan's reports stale so the next download re-renders them with the new statuses.

``GET /findings`` is the paged, filtered list across the latest scan of every project (or one
scan); ``/views`` stores a user's named filter sets and counts what each one matches. The detail
adds the derived fields of ``codekavach.server.insights``: baseline state, merged engines, SLA due
date, the model runs and the attack scenario and secure example the LLM tasks wrote.
"""

from pathlib import Path
from typing import Any, Final

from fastapi import APIRouter, Depends, Request
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
from codekavach.server.db.models import (
    FindingEvent,
    FindingRow,
    Project,
    SavedView,
    ScanRow,
    utcnow,
)
from codekavach.server.errors import ApiError, not_found
from codekavach.server.finding_query import FindingFilters, latest_scan_ids, list_findings
from codekavach.server.insights import (
    also_reported_by,
    baseline_states,
    consensus,
    exploit_scenario,
    llm_runs,
    merged_engines,
    remediation_example,
    review_level,
    sla,
    sla_policy,
    verdict_word,
)
from codekavach.server.rbac import Permission, permitted
from codekavach.server.results import finding_detail
from codekavach.server.schemas import FindingPatch, ViewCreate
from codekavach.server.state import ServerState, new_id

router = APIRouter(tags=["findings"])
ReadDep = Depends(require(Permission.read))
TriageDep = Depends(require(Permission.finding_triage))
BUILTIN_VIEWS: Final[tuple[tuple[str, str, dict[str, str]], ...]] = (
    ("all", "All findings", {}),
    ("open", "Open", {"status": "open,confirmed"}),
    ("critical-high", "Critical and high", {"severity": "critical,high",
                                            "status": "open,confirmed"}),
    ("mine", "Assigned to me", {"assignee": "me"}),
    ("llm-confirmed", "Confirmed by the LLM", {"verdict": "vulnerable"}),
    ("new", "New since the baseline", {"baseline_state": "new"}),
    ("suppressed", "Suppressed", {"status": "accepted_risk,false_positive"}),
)  # fmt: skip


def event_json(event: FindingEvent) -> dict[str, Any]:
    """The JSON of one history entry."""
    return {
        "id": event.id,
        "at": as_utc(event.at),
        "actor": event.actor,
        "action": event.action,
        "from_status": event.from_status,
        "to_status": event.to_status,
        "assignee": event.assignee,
        "comment": event.comment,
    }


def _scope(session: Session, scan_id: str | None, project_id: str | None) -> list[str]:
    if scan_id:
        if session.get(ScanRow, scan_id) is None:
            raise not_found("scan")
        return [scan_id]
    ids = latest_scan_ids(session)
    if project_id:
        rows = session.scalars(select(ScanRow).where(ScanRow.id.in_(ids)))
        ids = [row.id for row in rows if row.project_id == project_id]
    return ids


@router.get("/findings")
def list_all_findings(
    state: StateDep,
    session: SessionDep,
    scan_id: str | None = None,
    project_id: str | None = None,
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
    view: str | None = None,
    offset: int = 0,
    limit: int = 50,
    principal: Principal = ReadDep,
) -> dict[str, Any]:
    """Findings of one scan, or of the latest scan of every project: ``{items, total, ...}``.

    ``view`` applies a built-in or saved view first; explicit filters override its values.
    """
    given = FindingFilters(
        severity=severity, status=status, cwe=cwe, q=q, engine=engine, path=path,
        language=language, verdict=verdict, level=level, owasp=owasp, assignee=assignee,
        baseline_state=baseline_state,
    )  # fmt: skip
    values = _view_filters(session, principal, view) if view else {}
    values.update(given.as_dict())
    filters = FindingFilters.from_mapping(values)
    page = list_findings(
        session, _scope(session, scan_id, project_id), filters, settings=state.get_settings(),
        offset=offset, limit=limit, baseline=baseline, me=principal.username,
    )  # fmt: skip
    page["filters"] = filters.as_dict()
    return page


def _view_filters(session: Session, principal: Principal, view: str) -> dict[str, Any]:
    for key, _name, filters in BUILTIN_VIEWS:
        if key == view:
            return dict(filters)
    row = session.get(SavedView, view)
    if row is None or row.user_id != principal.user_id:
        raise not_found("view")
    return dict(row.filters or {})


def finding_json(
    session: Session, state: ServerState, finding_id: str, principal: Principal | None
) -> dict[str, Any]:
    """Everything about one finding: code, taint path, LLM verdict and runs, risk, SLA."""
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise not_found("finding")
    scan = session.get(ScanRow, row.scan_id)
    source = Path(scan.workspace) / "src" if scan is not None and scan.workspace else None
    detail = finding_detail(row, source)
    data = row.data or {}
    detail["verdict"] = verdict_word(data)
    detail["privacy_level"] = review_level(data) or (scan.privacy_level if scan else None)
    detail.update(sla(row, sla_policy(state.get_settings())))
    if scan is not None:
        project = session.get(Project, scan.project_id)
        detail["scan"] = {
            "id": scan.id,
            "project_id": scan.project_id,
            "project_name": project.name if project else None,
            "privacy_level": scan.privacy_level,
            "provider": scan.provider,
            "model": scan.model,
        }
        base_id, states, _fixed = baseline_states(session, scan, None)
        detail["baseline_scan_id"] = base_id
        detail["baseline_state"] = states.get(row.id, "new") if base_id else None
        detail["engines"] = merged_engines(row, also_reported_by(scan))
    else:
        detail["baseline_scan_id"] = detail["baseline_state"] = None
        detail["engines"] = merged_engines(row, {})
    detail["merged_from"] = len(detail["engines"])
    ledger: list[dict[str, Any]] = []
    if (
        scan is not None
        and principal is not None
        and permitted(principal.role, Permission.ledger_read)
        and scan.status == "completed"
    ):
        ledger = _ledger_for(state, session, scan, data)
    runs = llm_runs(data, ledger)
    llm = detail.get("llm")
    if isinstance(llm, dict):
        llm["runs"] = runs
        llm["consensus"] = consensus(runs)
        llm["temperature"] = None
        llm["exploit_scenario"] = exploit_scenario(
            llm.get("impact") or (data.get("impact") or {}).get("narrative")
        )
        llm["remediation_example"] = remediation_example(llm.get("remediation"))
    detail["exploit_scenario"] = exploit_scenario((data.get("impact") or {}).get("narrative"))
    detail["remediation_example"] = remediation_example(detail.get("remediation"))
    detail["remediation_diff"] = None
    history = session.scalars(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id).order_by(FindingEvent.id)
    )
    detail["history"] = [event_json(event) for event in history]
    return detail


def _ledger_for(
    state: ServerState, session: Session, scan: ScanRow, data: dict[str, Any]
) -> list[dict[str, Any]]:
    """Ledger rows (metadata only) of the finding's candidates."""
    from codekavach.server.routers.scans import finding_map, scan_results  # noqa: PLC0415

    candidates = {str(c) for c in (data.get("provenance") or {}).get("candidate_ids") or []}
    if not candidates:
        return []
    try:
        rows = scan_results(state, scan).ledger_rows(finding_map(session, scan.id))
    except ApiError:
        return []
    return [entry for entry in rows if entry.get("candidate_id") in candidates]


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str, state: StateDep, session: SessionDep, principal: Principal = ReadDep
) -> dict[str, Any]:
    """Everything about one finding: code, taint path, LLM verdict, risk, compliance."""
    return finding_json(session, state, finding_id, principal)


@router.patch("/findings/{finding_id}")
def patch_finding(
    finding_id: str,
    body: FindingPatch,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Principal = TriageDep,
) -> dict[str, Any]:
    """Change the status or assignee of a finding, or comment on it."""
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise not_found("finding")
    if body.status is None and body.comment is None and body.assignee is None:
        raise ApiError(400, "empty_patch", "give a status, an assignee or a comment")
    previous = row.status
    action = "comment"
    if body.status is not None and body.status != row.status:
        row.status = body.status
        action = "status"
    if body.assignee is not None and body.assignee != (row.assignee or ""):
        row.assignee = body.assignee or None
        action = "status" if action == "status" else "assign"
    if action == "comment" and not (body.comment or "").strip():
        # Nothing changed and nothing was said: no history entry, no stale reports.
        return finding_json(session, state, finding_id, principal)
    row.updated_at = utcnow()
    session.add(
        FindingEvent(
            finding_id=finding_id,
            actor=principal.username,
            action=action,
            from_status=previous,
            to_status=row.status,
            assignee=row.assignee,
            comment=body.comment,
        )
    )
    scan = session.get(ScanRow, row.scan_id)
    if scan is not None and row.status != previous:
        # Reports show the status only, so only a status change makes them stale.
        scan.triage_updated_at = utcnow()
    audit.record(state.db, actor=principal.username, action=f"finding.{action}",
                 resource=finding_id, client=client_of(request),
                 detail={"from": previous, "to": row.status})  # fmt: skip
    session.flush()
    return finding_json(session, state, finding_id, principal)


@router.get("/findings/{finding_id}/history", dependencies=[ReadDep])
def finding_history(finding_id: str, session: SessionDep) -> list[dict[str, Any]]:
    """The triage history and comments of a finding, oldest first."""
    if session.get(FindingRow, finding_id) is None:
        raise not_found("finding")
    events = session.scalars(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id).order_by(FindingEvent.id)
    )
    return [event_json(event) for event in events]


# --- saved views ----------------------------------------------------------------------------


def _count(
    session: Session, state: ServerState, scope: list[str], filters: dict[str, Any], me: str
) -> int:
    page = list_findings(session, scope, FindingFilters.from_mapping(filters),
                         settings=state.get_settings(), limit=1, me=me)  # fmt: skip
    return int(page["total"])


@router.get("/views")
def list_views(
    state: StateDep,
    session: SessionDep,
    scan_id: str | None = None,
    project_id: str | None = None,
    principal: Principal = ReadDep,
) -> list[dict[str, Any]]:
    """The built-in views and the caller's saved views, each with the number it matches."""
    scope = _scope(session, scan_id, project_id)
    views: list[dict[str, Any]] = [
        {"id": key, "name": name, "filters": filters, "builtin": True, "created_at": None}
        for key, name, filters in BUILTIN_VIEWS
    ]
    saved = session.scalars(
        select(SavedView).where(SavedView.user_id == principal.user_id).order_by(
            SavedView.created_at)
    )  # fmt: skip
    views += [
        {"id": row.id, "name": row.name, "filters": dict(row.filters or {}), "builtin": False,
         "created_at": as_utc(row.created_at)}
        for row in saved
    ]  # fmt: skip
    for item in views:
        item["count"] = _count(session, state, scope, item["filters"], principal.username)
    return views


@router.post("/views", status_code=201)
def create_view(
    body: ViewCreate,
    state: StateDep,
    session: SessionDep,
    principal: Principal = ReadDep,
) -> dict[str, Any]:
    """Save a named set of findings filters for the caller."""
    filters = FindingFilters.from_mapping(body.filters).as_dict()
    row = SavedView(id=new_id("view"), user_id=principal.user_id, name=body.name,
                    filters=filters)  # fmt: skip
    session.add(row)
    session.flush()
    return {
        "id": row.id,
        "name": row.name,
        "filters": filters,
        "builtin": False,
        "created_at": as_utc(row.created_at),
        "count": _count(session, state, latest_scan_ids(session), filters, principal.username),
    }


@router.delete("/views/{view_id}")
def delete_view(
    view_id: str, session: SessionDep, principal: Principal = ReadDep
) -> dict[str, Any]:
    """Delete one of the caller's saved views."""
    row = session.get(SavedView, view_id)
    if row is None or row.user_id != principal.user_id:
        raise not_found("view")
    session.delete(row)
    return {"ok": True}
