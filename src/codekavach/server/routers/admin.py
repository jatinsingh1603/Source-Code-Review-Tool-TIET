"""Routes for administration: role change and revocation, API tokens, vault and retention status.

Owning epic: E32.

Every route needs ``users:admin`` and every change is audited. ``/vault`` reports the metadata of
each scan's mapping vault through ``codekavach.privacy.vault.info.vault_info`` with the key probe
off: the header, row counts and file times, never a mapping (I3). ``/retention`` reports what the
server stores and the configured vault retention. Organisations (tenants) and single sign-on do
not exist in this server: their routes answer 501 with a message saying so.
"""

import importlib
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from codekavach.core.log import get_logger
from codekavach.server import audit
from codekavach.server.auth.dependencies import (
    Principal,
    SessionDep,
    StateDep,
    client_of,
    require,
)
from codekavach.server.auth.tokens import revoke_user_tokens
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import ApiToken, ScanRow, User
from codekavach.server.errors import ApiError, not_found
from codekavach.server.rbac import Permission
from codekavach.server.results import ScanPaths
from codekavach.server.routers.auth import user_json
from codekavach.server.routers.platform import server_settings
from codekavach.server.schemas import RoleBody

_log = get_logger("codekavach.server.admin")

router = APIRouter(tags=["admin"])
AdminDep = Depends(require(Permission.users_admin))


def token_json(row: ApiToken, username: str | None = None) -> dict[str, Any]:
    """The public JSON of a personal token (never its hash or value)."""
    return {
        "id": row.id,
        "name": row.name,
        "prefix": row.prefix,
        "user_id": row.user_id,
        "username": username,
        "created_at": as_utc(row.created_at),
        "expires_at": as_utc(row.expires_at),
        "last_used_at": as_utc(row.last_used_at),
        "revoked": row.revoked,
    }


@router.put("/users/{user_id}/role")
def change_role(
    user_id: str,
    body: RoleBody,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Principal = AdminDep,
) -> dict[str, Any]:
    """Give a user another role; their sessions and tokens are revoked."""
    user = session.get(User, user_id)
    if user is None:
        raise not_found("user")
    if user.id == principal.user_id and body.role != "admin":
        raise ApiError(409, "self_lockout", "you cannot demote your own account")
    previous = user.role
    user.role = body.role
    revoked = revoke_user_tokens(session, user.id) if previous != body.role else 0
    audit.record(state.db, actor=principal.username, action="user.role", resource=user.id,
                 client=client_of(request), detail={"from": previous, "to": body.role})  # fmt: skip
    return {**user_json(user), "tokens_revoked": revoked}


@router.post("/users/{user_id}/revoke")
def revoke_user(
    user_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    disable: bool = True,
    principal: Principal = AdminDep,
) -> dict[str, Any]:
    """Revoke a user's access: every session and token, and (by default) the account itself."""
    user = session.get(User, user_id)
    if user is None:
        raise not_found("user")
    if user.id == principal.user_id:
        raise ApiError(409, "self_lockout", "you cannot revoke your own access")
    revoked = revoke_user_tokens(session, user.id)
    if disable:
        user.active = False
    audit.record(state.db, actor=principal.username, action="user.revoke", resource=user.id,
                 client=client_of(request),
                 detail={"tokens": revoked, "disabled": disable})  # fmt: skip
    return {**user_json(user), "tokens_revoked": revoked}


@router.get("/tokens", dependencies=[AdminDep])
def list_tokens(session: SessionDep, include_revoked: bool = False) -> list[dict[str, Any]]:
    """Every personal API token of every user (metadata only)."""
    names = {user.id: user.username for user in session.scalars(select(User))}
    query = select(ApiToken).order_by(ApiToken.created_at.desc())
    if not include_revoked:
        query = query.where(ApiToken.revoked.is_(False))
    return [token_json(row, names.get(row.user_id)) for row in session.scalars(query)]


@router.delete("/tokens/{token_id}")
def revoke_any_token(
    token_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Principal = AdminDep,
) -> dict[str, Any]:
    """Revoke any user's personal token."""
    row = session.get(ApiToken, token_id)
    if row is None:
        raise not_found("token")
    row.revoked = True
    audit.record(state.db, actor=principal.username, action="token.revoke", resource=token_id,
                 client=client_of(request), detail={"user_id": row.user_id})  # fmt: skip
    return {"ok": True}


@router.get("/vault", dependencies=[AdminDep])
def vault_status(state: StateDep, session: SessionDep) -> dict[str, Any]:
    """Metadata of every scan's mapping vault: no key is probed and no mapping is read (I3)."""
    # Loaded by name, as the CLI loads the vault back end: the server imports nothing of the
    # vault package statically (the MappingRecord contract), and ``vault_info`` reads only the
    # header, row counts and file times, never a record (I3).
    info_module = importlib.import_module("codekavach.privacy.vault.info")
    vault_error = importlib.import_module("codekavach.privacy.vault.errors").VaultError
    vault_info = info_module.vault_info

    settings = server_settings(state)
    vaults: list[dict[str, Any]] = []
    for scan in session.scalars(select(ScanRow).order_by(ScanRow.created_at.desc())):
        if not scan.workspace:
            continue
        state_dir = ScanPaths(Path(scan.workspace)).state_dir
        if not state_dir.is_dir():
            continue
        try:
            info = vault_info(state_dir, settings=settings, probe=False)
        except vault_error:
            continue
        except Exception as error:  # noqa: BLE001 - one unreadable vault is a row, not a 500
            vaults.append({"scan_id": scan.id, "error": type(error).__name__})
            continue
        try:
            size = info.path.stat().st_size
        except OSError:
            size = None
        vaults.append(
            {
                "scan_id": scan.id,
                "project_id": scan.project_id,
                "format_version": info.format_version,
                "key_source": info.key_source,
                "records": info.record_count,
                "created_at": info.created_at,
                "last_write_at": info.last_write_at,
                "rotated_at": info.rotated_at,
                "rotations": info.rotation_count,
                "size_bytes": size,
            }
        )
    return {
        "vaults": vaults,
        "count": len(vaults),
        "records": sum(int(item.get("records") or 0) for item in vaults),
        "retention_days": settings.privacy.vault.retention_days,
        "key_source": state.passphrase_origin,
        "note": "metadata only: the server never returns or logs a vault mapping",
    }


def _tree_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


@router.get("/retention", dependencies=[AdminDep])
def retention(state: StateDep, session: SessionDep) -> dict[str, Any]:
    """What the server keeps on disk and the configured retention of vault mappings."""
    settings = server_settings(state)
    scans = session.scalar(select(func.count()).select_from(ScanRow)) or 0
    oldest = session.scalar(select(func.min(ScanRow.created_at)))
    newest = session.scalar(select(func.max(ScanRow.created_at)))
    config = state.config
    return {
        "scans": scans,
        "oldest_scan_at": as_utc(oldest),
        "newest_scan_at": as_utc(newest),
        "scans_bytes": _tree_size(config.scans_dir) if config.scans_dir.is_dir() else 0,
        "uploads_bytes": _tree_size(config.uploads_dir) if config.uploads_dir.is_dir() else 0,
        "database_bytes": config.db_path.stat().st_size if config.db_path.is_file() else 0,
        "vault_retention_days": settings.privacy.vault.retention_days,
        "ledger_payloads": "kept with each scan until the scan is deleted",
        "automatic_purge": False,
        "how_to_purge": "DELETE /api/v1/scans/{id} removes a scan's workspace, vault and ledger",
    }


def _not_implemented(feature: str) -> ApiError:
    return ApiError(
        501,
        "not_implemented",
        f"{feature} is not available in this server: it has one organisation and local accounts",
        hint="see docs/reference/api.md, section 'Not implemented'",
    )


@router.get("/orgs", dependencies=[AdminDep])
def organisations() -> dict[str, Any]:
    """Organisations (tenants) are not implemented."""
    raise _not_implemented("organisation management")


@router.get("/auth/sso")
def sso() -> dict[str, Any]:
    """Single sign-on (SAML, OIDC) is not implemented."""
    raise _not_implemented("single sign-on (SAML / OIDC)")
