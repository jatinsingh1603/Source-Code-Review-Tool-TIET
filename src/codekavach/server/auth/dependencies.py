"""FastAPI dependencies: the server state, a database session, the principal and ``require``.

Owning epic: E32.

``require(permission)`` is the single authorisation dependency: it authenticates the bearer token
(``Authorization: Bearer ck_...``, or ``?access_token=`` for ``EventSource`` and download links,
which cannot send headers), checks the role against the matrix in ``rbac`` and writes a ``denied``
audit event when the role lacks the permission.
"""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from codekavach.server import audit
from codekavach.server.auth.tokens import authenticate_token
from codekavach.server.errors import ApiError
from codekavach.server.rbac import Permission, permitted
from codekavach.server.state import ServerState


@dataclass(frozen=True)
class Principal:
    """The authenticated caller."""

    user_id: str
    username: str
    role: str
    token: str


def get_state(request: Request) -> ServerState:
    """The ``ServerState`` of the application."""
    state: ServerState = request.app.state.server
    return state


StateDep = Annotated[ServerState, Depends(get_state)]


def get_session(state: StateDep) -> Iterator[Session]:
    """A session committed after the handler returns, rolled back on error."""
    with state.db.transaction() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def client_of(request: Request) -> str:
    """The client address (for audit and rate limiting)."""
    return request.client.host if request.client else "unknown"


def bearer_token(request: Request) -> str | None:
    """The bearer token of the request, from the header or the ``access_token`` parameter.

    The query parameter is for ``EventSource`` streams and download links, which cannot send
    headers, so it is accepted on ``GET`` only: a request that changes state needs the header.
    """
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    if request.method not in {"GET", "HEAD"}:
        return None
    token = request.query_params.get("access_token")
    return token or None


def current_principal(request: Request, state: StateDep) -> Principal:
    """The caller; 401 without a valid token."""
    raw = bearer_token(request)
    if raw is None:
        raise ApiError(401, "unauthenticated", "authentication required", "log in first")
    with state.db.transaction() as session:
        user = authenticate_token(session, raw)
        if user is None:
            raise ApiError(401, "invalid_token", "the token is invalid or has expired")
        principal = Principal(user.id, user.username, user.role, raw)
    request.state.principal = principal
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


def require(permission: Permission) -> Callable[..., Principal]:
    """A dependency that admits only principals whose role holds ``permission``."""

    def dependency(request: Request, state: StateDep, principal: PrincipalDep) -> Principal:
        if not permitted(principal.role, permission):
            audit.record(
                state.db,
                actor=principal.username,
                action=f"{request.method} {request.url.path}",
                resource=str(permission),
                outcome="denied",
                client=client_of(request),
            )
            raise ApiError(
                403,
                "forbidden",
                f"the role {principal.role} lacks the permission {permission}",
            )
        return principal

    dependency.permission = permission  # type: ignore[attr-defined]
    return dependency
