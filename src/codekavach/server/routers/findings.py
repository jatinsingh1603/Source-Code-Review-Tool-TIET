"""Routes ``/findings/{id}``: detail, triage (status, assignee, comment) and history.

Owning epic: E32.

Triage is server state: the finding JSON the pipeline produced is kept as it was, and the status,
assignee and an append-only history of changes and comments are stored beside it. A change marks
the scan's reports stale so the next download re-renders them with the new statuses.
"""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from codekavach.server import audit
from codekavach.server.auth.dependencies import SessionDep, StateDep, client_of, require
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import FindingEvent, FindingRow, Project, ScanRow, utcnow
from codekavach.server.errors import ApiError, not_found
from codekavach.server.rbac import Permission
from codekavach.server.results import finding_detail
from codekavach.server.schemas import FindingPatch

router = APIRouter(tags=["findings"])
ReadDep = Depends(require(Permission.read))
TriageDep = Depends(require(Permission.finding_triage))


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


@router.get("/findings/{finding_id}", dependencies=[ReadDep])
def get_finding(finding_id: str, session: SessionDep) -> dict[str, Any]:
    """Everything about one finding: code, taint path, LLM verdict, risk, compliance."""
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise not_found("finding")
    scan = session.get(ScanRow, row.scan_id)
    source = Path(scan.workspace) / "src" if scan is not None and scan.workspace else None
    detail = finding_detail(row, source)
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
    history = session.scalars(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id).order_by(FindingEvent.id)
    )
    detail["history"] = [event_json(event) for event in history]
    return detail


@router.patch("/findings/{finding_id}")
def patch_finding(
    finding_id: str,
    body: FindingPatch,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = TriageDep,
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
    if scan is not None:
        scan.triage_updated_at = utcnow()
    audit.record(state.db, actor=principal.username, action=f"finding.{action}",
                 resource=finding_id, client=client_of(request),
                 detail={"from": previous, "to": row.status})  # fmt: skip
    session.flush()
    return get_finding(finding_id, session)


@router.get("/findings/{finding_id}/history", dependencies=[ReadDep])
def finding_history(finding_id: str, session: SessionDep) -> list[dict[str, Any]]:
    """The triage history and comments of a finding, oldest first."""
    if session.get(FindingRow, finding_id) is None:
        raise not_found("finding")
    events = session.scalars(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id).order_by(FindingEvent.id)
    )
    return [event_json(event) for event in events]
