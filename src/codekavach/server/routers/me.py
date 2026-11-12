"""Routes ``/me``: the caller's profile, preferences, notification settings, tokens and feed.

Owning epic: E32.

Any signed-in user may change their own name and e-mail address, store display preferences and
notification switches, and create or revoke personal API tokens (shown once, stored as SHA-256).
Notification settings are stored only: the server sends no e-mail or message. ``/notifications``
is a feed built from server records the user can already read (scans that finished, findings
assigned to them); the read marker is kept in the preferences.
"""

from datetime import datetime
from typing import Any, Final

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.server import audit
from codekavach.server.auth.dependencies import (
    Principal,
    PrincipalDep,
    SessionDep,
    StateDep,
    client_of,
    require,
)
from codekavach.server.auth.tokens import issue_api_token
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import (
    ApiToken,
    FindingEvent,
    FindingRow,
    Project,
    ScanRow,
    User,
    UserPreference,
    utcnow,
)
from codekavach.server.errors import ApiError, not_found
from codekavach.server.rbac import Permission
from codekavach.server.routers.admin import token_json
from codekavach.server.routers.auth import user_json
from codekavach.server.schemas import (
    NotificationsBody,
    PreferencesBody,
    ProfileUpdate,
    TokenCreate,
)
from codekavach.server.state import new_id

router = APIRouter(tags=["me"])
ReadDep = Depends(require(Permission.read))
DEFAULT_PREFERENCES: Final[dict[str, Any]] = {
    "theme": "system",
    "density": "comfortable",
    "reduce_motion": False,
    "language": "en-GB",
    "time_zone": "Asia/Kolkata",
    "date_format": "long",
}
NOTIFICATION_EVENTS: Final = (
    "scan_completed",
    "scan_failed",
    "finding_assigned",
    "critical_finding",
    "ledger_verification_failed",
)
DEFAULT_NOTIFICATIONS: Final[dict[str, dict[str, bool]]] = {
    event: {"in_app": True, "email": False} for event in NOTIFICATION_EVENTS
}
MAX_TOKENS_PER_USER: Final = 20


def _stored(session: Session, user_id: str) -> dict[str, Any]:
    row = session.get(UserPreference, user_id)
    return dict(row.value) if row is not None else {}


def _store(session: Session, user_id: str, value: dict[str, Any]) -> None:
    row = session.get(UserPreference, user_id)
    if row is None:
        session.add(UserPreference(user_id=user_id, value=value))
    else:
        row.value = value


def _user(session: Session, principal: Any) -> User:
    user = session.get(User, principal.user_id)
    if user is None:
        raise ApiError(401, "invalid_token", "the user no longer exists")
    return user


@router.get("/me")
def get_me(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    """The current user with their preferences."""
    user = _user(session, principal)
    stored = _stored(session, user.id)
    return {
        **user_json(user),
        "preferences": {**DEFAULT_PREFERENCES, **stored.get("preferences", {})},
    }


@router.patch("/me")
def update_me(
    body: ProfileUpdate,
    request: Request,
    principal: PrincipalDep,
    state: StateDep,
    session: SessionDep,
) -> dict[str, Any]:
    """Change the caller's display name or e-mail address."""
    user = _user(session, principal)
    changes = body.model_dump(exclude_none=True)
    if "display_name" in changes:
        user.full_name = changes["display_name"]
    if "email" in changes:
        user.email = changes["email"]
    audit.record(state.db, actor=principal.username, action="user.profile", resource=user.id,
                 client=client_of(request), detail={"fields": sorted(changes)})  # fmt: skip
    return user_json(user)


@router.get("/me/preferences")
def get_preferences(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    """Display preferences (defaults filled in)."""
    stored = _stored(session, principal.user_id)
    return {**DEFAULT_PREFERENCES, **stored.get("preferences", {})}


@router.patch("/me/preferences")
def patch_preferences(
    body: PreferencesBody, principal: PrincipalDep, session: SessionDep
) -> dict[str, Any]:
    """Store display preferences."""
    stored = _stored(session, principal.user_id)
    preferences = {**stored.get("preferences", {}), **body.model_dump(exclude_none=True)}
    if "time_zone" in preferences:
        _check_zone(str(preferences["time_zone"]))
    _store(session, principal.user_id, {**stored, "preferences": preferences})
    return {**DEFAULT_PREFERENCES, **preferences}


def _check_zone(name: str) -> None:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError  # noqa: PLC0415

    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ApiError(400, "invalid_time_zone", f"unknown time zone {name}") from None


@router.get("/me/notifications")
def get_notification_settings(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    """Event to channel switches; stored only, the server sends nothing."""
    stored = _stored(session, principal.user_id).get("notifications", {})
    events = {event: {**DEFAULT_NOTIFICATIONS[event], **stored.get(event, {})}
              for event in NOTIFICATION_EVENTS}  # fmt: skip
    return {"events": events, "delivery": "stored only; no e-mail or message is sent"}


@router.patch("/me/notifications")
def patch_notification_settings(
    body: NotificationsBody, principal: PrincipalDep, session: SessionDep
) -> dict[str, Any]:
    """Store the switches of known events and channels."""
    unknown = sorted(set(body.events) - set(NOTIFICATION_EVENTS))
    if unknown:
        raise ApiError(400, "unknown_event", f"unknown notification event {unknown[0]}")
    for switches in body.events.values():
        if set(switches) - {"in_app", "email"}:
            raise ApiError(400, "unknown_channel", "channels are in_app and email")
    stored = _stored(session, principal.user_id)
    current = dict(stored.get("notifications", {}))
    for event, switches in body.events.items():
        current[event] = {**current.get(event, {}), **switches}
    _store(session, principal.user_id, {**stored, "notifications": current})
    return get_notification_settings(principal, session)


@router.get("/me/tokens")
def my_tokens(principal: PrincipalDep, session: SessionDep) -> list[dict[str, Any]]:
    """The caller's personal API tokens (metadata only)."""
    rows = session.scalars(
        select(ApiToken)
        .where(ApiToken.user_id == principal.user_id, ApiToken.revoked.is_(False))
        .order_by(ApiToken.created_at.desc())
    )
    return [token_json(row, principal.username) for row in rows]


@router.post("/me/tokens", status_code=201)
def create_token(
    body: TokenCreate,
    request: Request,
    principal: PrincipalDep,
    state: StateDep,
    session: SessionDep,
) -> dict[str, Any]:
    """Create a personal API token; its value is in this response only."""
    user = _user(session, principal)
    active = session.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id, ApiToken.revoked.is_(False))
    ).all()
    if len(active) >= MAX_TOKENS_PER_USER:
        raise ApiError(409, "too_many_tokens", f"at most {MAX_TOKENS_PER_USER} active tokens")
    row, raw = issue_api_token(session, user, token_id=new_id("tok"), name=body.name,
                               ttl_days=body.expires_in_days)  # fmt: skip
    session.flush()
    audit.record(state.db, actor=principal.username, action="token.create", resource=row.id,
                 client=client_of(request), detail={"name": body.name})  # fmt: skip
    return {**token_json(row, principal.username), "token": raw}


@router.delete("/me/tokens/{token_id}")
def revoke_my_token(
    token_id: str,
    request: Request,
    principal: PrincipalDep,
    state: StateDep,
    session: SessionDep,
) -> dict[str, Any]:
    """Revoke one of the caller's tokens."""
    row = session.get(ApiToken, token_id)
    if row is None or row.user_id != principal.user_id:
        raise not_found("token")
    row.revoked = True
    audit.record(state.db, actor=principal.username, action="token.revoke", resource=token_id,
                 client=client_of(request))  # fmt: skip
    return {"ok": True}


# --- notifications feed ---------------------------------------------------------------------


def _read_at(session: Session, user_id: str) -> datetime | None:
    value = _stored(session, user_id).get("notifications_read_at")
    try:
        return as_utc(datetime.fromisoformat(value)) if isinstance(value, str) else None
    except ValueError:
        return None


@router.get("/notifications")
def notifications(
    session: SessionDep, limit: int = 30, principal: Principal = ReadDep
) -> dict[str, Any]:
    """Recent events for the caller: finished scans and findings assigned to them."""
    size = max(1, min(limit, 200))
    names = {row.id: row.name for row in session.scalars(select(Project))}
    items: list[dict[str, Any]] = []
    scans = session.scalars(
        select(ScanRow)
        .where(ScanRow.status.in_(["completed", "failed"]))
        .order_by(ScanRow.finished_at.desc())
        .limit(size)
    )
    for scan in scans:
        failed = scan.status == "failed"
        items.append({
            "id": f"scan:{scan.id}",
            "event": "scan_failed" if failed else "scan_completed",
            "at": as_utc(scan.finished_at),
            "title": f"Scan {'failed' if failed else 'completed'}: "
                     f"{names.get(scan.project_id, scan.project_id)}",
            "link": f"/scans/{scan.id}",
        })  # fmt: skip
    assigned = session.execute(
        select(FindingEvent, FindingRow.title)
        .join(FindingRow, FindingRow.id == FindingEvent.finding_id)
        .where(FindingEvent.assignee == principal.username, FindingEvent.action == "assign")
        .order_by(FindingEvent.at.desc())
        .limit(size)
    )
    for event, title in assigned:
        items.append({"id": f"assign:{event.id}", "event": "finding_assigned",
                      "at": as_utc(event.at), "title": f"Assigned to you: {title}",
                      "link": f"/findings/{event.finding_id}"})  # fmt: skip
    items.sort(key=lambda item: item["at"] or utcnow(), reverse=True)
    items = items[:size]
    read_at = _read_at(session, principal.user_id)
    for item in items:
        item["read"] = read_at is not None and item["at"] is not None and item["at"] <= read_at
    return {"items": items, "unread": sum(1 for item in items if not item["read"])}


@router.post("/notifications/read")
def mark_read(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    """Mark every notification so far as read."""
    stored = _stored(session, principal.user_id)
    now = utcnow()
    _store(session, principal.user_id, {**stored, "notifications_read_at": now.isoformat()})
    return {"ok": True, "read_at": now}
