"""Routes ``/auth/*`` and ``/users``: login, logout, the current user, user administration.

Owning epic: E32.

Login is rate-limited per client address and per user name and answers an unknown user and a
wrong password identically (same code, same work through ``DUMMY_HASH``). Every login, logout and
user change is audited. Changing a user's role, password or active flag revokes their tokens.
"""

from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select

from codekavach.server import audit
from codekavach.server.auth.dependencies import (
    PrincipalDep,
    SessionDep,
    StateDep,
    client_of,
    require,
)
from codekavach.server.auth.passwords import (
    DUMMY_HASH,
    hash_password,
    needs_rehash,
    verify_password,
)
from codekavach.server.auth.tokens import issue_token, revoke_token, revoke_user_tokens
from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import User, utcnow
from codekavach.server.errors import ApiError, not_found
from codekavach.server.rbac import PERMISSIONS, Permission, Role
from codekavach.server.schemas import LoginBody, UserCreate, UserUpdate
from codekavach.server.state import new_id

router = APIRouter(tags=["auth"])


def user_json(user: User) -> dict[str, Any]:
    """The public JSON of a user (never the password hash)."""
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "active": user.active,
        "created_at": as_utc(user.created_at),
        "last_login": as_utc(user.last_login),
        "permissions": sorted(str(item) for item in PERMISSIONS.get(Role(user.role), ())),
    }


@router.post("/auth/login")
def login(
    body: LoginBody, request: Request, state: StateDep, session: SessionDep
) -> dict[str, Any]:
    """Exchange a user name and password for a bearer token."""
    client = client_of(request)
    for key in (f"ip:{client}", f"user:{body.username.lower()}"):
        wait = state.login_limiter.hit(key)
        if wait is not None:
            audit.record(state.db, actor=body.username[:64], action="auth.login",
                         outcome="rate_limited", client=client)  # fmt: skip
            raise ApiError(429, "rate_limited", "too many login attempts; try again shortly",
                           hint=f"retry after {int(wait)} s",
                           headers={"Retry-After": str(int(wait))})  # fmt: skip
    user = session.scalars(select(User).where(User.username == body.username)).first()
    valid = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if user is None or not valid or not user.active:
        audit.record(state.db, actor=body.username[:64], action="auth.login", outcome="failed",
                     client=client)  # fmt: skip
        raise ApiError(401, "invalid_credentials", "invalid user name or password")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.last_login = utcnow()
    token = issue_token(session, user, state.config.token_ttl_seconds)
    state.login_limiter.reset(f"user:{body.username.lower()}")
    audit.record(state.db, actor=user.username, action="auth.login", client=client)
    return {
        "token": token,
        "token_type": "bearer",
        "expires_in": state.config.token_ttl_seconds,
        "user": user_json(user),
    }


@router.get("/auth/me")
def me(principal: PrincipalDep, session: SessionDep) -> dict[str, Any]:
    """The current user."""
    user = session.get(User, principal.user_id)
    if user is None:
        raise ApiError(401, "invalid_token", "the user no longer exists")
    return user_json(user)


@router.post("/auth/logout")
def logout(
    request: Request, principal: PrincipalDep, state: StateDep, session: SessionDep
) -> dict[str, Any]:
    """Revoke the current token."""
    revoke_token(session, principal.token)
    audit.record(state.db, actor=principal.username, action="auth.logout",
                 client=client_of(request))  # fmt: skip
    return {"ok": True}


AdminDep = Depends(require(Permission.users_admin))


@router.get("/users", dependencies=[AdminDep])
def list_users(session: SessionDep) -> list[dict[str, Any]]:
    """Every user."""
    return [user_json(user) for user in session.scalars(select(User).order_by(User.username))]


@router.post("/users", status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = AdminDep,
) -> dict[str, Any]:
    """Create a user."""
    exists = session.scalars(select(User).where(User.username == body.username)).first()
    if exists is not None:
        raise ApiError(409, "user_exists", f"the user {body.username} already exists")
    user = User(
        id=new_id("usr"),
        username=body.username,
        full_name=body.full_name,
        email=body.email,
        role=body.role,
        password_hash=hash_password(body.password),
    )
    session.add(user)
    audit.record(state.db, actor=principal.username, action="user.create", resource=user.id,
                 client=client_of(request), detail={"role": body.role})  # fmt: skip
    return user_json(user)


@router.patch("/users/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdate,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = AdminDep,
) -> dict[str, Any]:
    """Change a user's role, password, name, e-mail or active flag."""
    user = session.get(User, user_id)
    if user is None:
        raise not_found("user")
    changes = body.model_dump(exclude_none=True)
    if user.id == principal.user_id and (
        changes.get("role", "admin") != "admin" or changes.get("active") is False
    ):
        raise ApiError(409, "self_lockout", "you cannot demote or disable your own account")
    if "password" in changes:
        user.password_hash = hash_password(changes.pop("password"))
        revoke_user_tokens(session, user.id)
    for key in ("role", "full_name", "email", "active"):
        if key in changes:
            setattr(user, key, changes[key])
    if "role" in changes or changes.get("active") is False:
        revoke_user_tokens(session, user.id)
    audit.record(state.db, actor=principal.username, action="user.update", resource=user.id,
                 client=client_of(request), detail={"fields": sorted(changes)})  # fmt: skip
    return user_json(user)


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    request: Request,
    state: StateDep,
    session: SessionDep,
    principal: Any = AdminDep,
) -> dict[str, Any]:
    """Delete a user (not yourself)."""
    user = session.get(User, user_id)
    if user is None:
        raise not_found("user")
    if user.id == principal.user_id:
        raise ApiError(409, "self_lockout", "you cannot delete your own account")
    revoke_user_tokens(session, user.id)
    session.delete(user)
    audit.record(state.db, actor=principal.username, action="user.delete", resource=user_id,
                 client=client_of(request))  # fmt: skip
    return {"ok": True}
