"""Routes ``/auth/providers`` and ``/auth/google/*``: optional Google sign-in.

Owning epic: E32.

Without ``CODEKAVACH_GOOGLE_CLIENT_ID`` and ``CODEKAVACH_GOOGLE_CLIENT_SECRET`` the two Google
routes answer 404 and ``/auth/providers`` says the provider is off. A completed sign-in issues the
same session token as a password login and hands it to the dashboard in the URL fragment, which
browsers do not send to servers or write to access logs. Failures redirect to the login page with
a short code and no detail.
"""

import secrets
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.server import audit
from codekavach.server.auth import google
from codekavach.server.auth.dependencies import SessionDep, StateDep, client_of
from codekavach.server.auth.passwords import hash_password
from codekavach.server.auth.tokens import issue_token
from codekavach.server.db.models import User, utcnow
from codekavach.server.errors import not_found
from codekavach.server.state import ServerState, new_id

router = APIRouter(tags=["auth"])

STATE_KEY_FILE = "google-sso-state.key"
COOKIE_PATH = "/api/v1/auth/google"


def _config(state: ServerState) -> google.GoogleSso:
    config = state.config.google
    if config is None:
        raise not_found("endpoint")
    return config


def _base(config: google.GoogleSso, request: Request) -> str:
    return config.public_url or str(request.base_url).rstrip("/")


@router.get("/auth/providers")
def providers(state: StateDep) -> dict[str, Any]:
    """Which sign-in providers besides the local accounts are switched on."""
    return {"google": {"enabled": state.config.google is not None}}


@router.get("/auth/google/login")
def google_login(request: Request, state: StateDep) -> RedirectResponse:
    """Send the browser to Google with a fresh state, nonce and PKCE challenge."""
    config = _config(state)
    base = _base(config, request)
    pending = google.Pending.new()
    response = RedirectResponse(google.authorization_url(config, pending, base), status_code=302)
    response.set_cookie(
        google.STATE_COOKIE,
        pending.seal(state.config.secret_file(STATE_KEY_FILE)),
        max_age=google.STATE_TTL_SECONDS,
        path=COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=base.startswith("https://"),
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _sign_in(
    request: Request, state: ServerState, session: Session, config: google.GoogleSso, base: str
) -> str:
    cookie = request.cookies.get(google.STATE_COOKIE, "")
    pending = google.Pending.open(cookie, state.config.secret_file(STATE_KEY_FILE))
    returned = request.query_params.get("state", "")
    if not returned or not secrets.compare_digest(returned.encode(), pending.state.encode()):
        raise google.SsoError("state")
    code = request.query_params.get("code", "")
    if request.query_params.get("error") or not code:
        raise google.SsoError("denied")
    exchange: google.Exchange = getattr(request.app.state, "google_exchange", google.exchange_code)
    tokens = exchange(config, code, pending.verifier, google.redirect_uri(base))
    identity = google.verify_id_token(config, tokens, pending.nonce)
    user = session.scalars(select(User).where(User.username == identity.email)).first()
    client = client_of(request)
    if user is None:
        # No local password: the stored hash is of a random value nobody ever saw.
        user = User(
            id=new_id("usr"),
            username=identity.email,
            full_name=identity.name,
            email=identity.email,
            role=config.default_role,
            password_hash=hash_password(secrets.token_urlsafe(32)),
        )
        session.add(user)
        session.flush()
        audit.record(state.db, actor=identity.email, action="user.create", resource=user.id,
                     client=client, detail={"role": user.role, "method": "google"})  # fmt: skip
    elif not user.active:
        raise google.SsoError("disabled")
    user.last_login = utcnow()
    token = issue_token(session, user, state.config.token_ttl_seconds)
    audit.record(state.db, actor=user.username, action="auth.login", client=client,
                 detail={"method": "google"})  # fmt: skip
    return token


@router.get("/auth/google/callback")
def google_callback(request: Request, state: StateDep, session: SessionDep) -> RedirectResponse:
    """Finish the sign-in and return to the dashboard with a session token in the fragment."""
    config = _config(state)
    base = _base(config, request)
    try:
        token = _sign_in(request, state, session, config, base)
        response = RedirectResponse(f"{base}/login#sso_token={token}", status_code=302)
    except google.SsoError as error:
        audit.record(state.db, actor="google", action="auth.login", outcome="failed",
                     client=client_of(request),
                     detail={"method": "google", "reason": error.code})  # fmt: skip
        response = RedirectResponse(f"{base}/login?sso_error={error.code}", status_code=302)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.delete_cookie(google.STATE_COOKIE, path=COOKIE_PATH)
    return response
