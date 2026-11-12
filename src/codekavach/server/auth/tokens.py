"""Opaque bearer tokens: issue, authenticate, revoke.

Owning epic: E32.

A token is ``ck_`` plus 32 random bytes in URL-safe base64. Only its SHA-256 is stored, so a copy
of the database does not yield a usable token. Tokens expire after the configured lifetime and
stop working as soon as they are revoked (logout) or their user is disabled.

Personal API tokens (``ApiToken``) use the same format with the ``ck_pat_`` prefix; they carry a
name, an optional expiry and the time of their last use, and are revoked one by one.
"""

import hashlib
import secrets
from datetime import timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import ApiToken, SessionToken, User, utcnow

TOKEN_PREFIX: Final = "ck_"  # noqa: S105 - a format prefix, not a secret
API_TOKEN_PREFIX: Final = "ck_pat_"  # noqa: S105 - a format prefix, not a secret


def token_hash(raw: str) -> str:
    """The stored form of ``raw``."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_token(session: Session, user: User, ttl_seconds: int) -> str:
    """A new token for ``user``; the plaintext is returned once and never stored."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    session.add(
        SessionToken(
            token_hash=token_hash(raw),
            user_id=user.id,
            expires_at=utcnow() + timedelta(seconds=ttl_seconds),
        )
    )
    return raw


def authenticate_token(session: Session, raw: str) -> User | None:
    """The active user of a valid, unexpired, unrevoked token; ``None`` otherwise."""
    if not raw.startswith(TOKEN_PREFIX):
        return None
    if raw.startswith(API_TOKEN_PREFIX):
        return _authenticate_api_token(session, raw)
    row = session.get(SessionToken, token_hash(raw))
    if row is None or row.revoked:
        return None
    expires = as_utc(row.expires_at)
    if expires is None or expires <= utcnow():
        return None
    user = session.get(User, row.user_id)
    if user is None or not user.active:
        return None
    return user


def _authenticate_api_token(session: Session, raw: str) -> User | None:
    row = session.scalars(select(ApiToken).where(ApiToken.token_hash == token_hash(raw))).first()
    if row is None or row.revoked:
        return None
    expires = as_utc(row.expires_at)
    if expires is not None and expires <= utcnow():
        return None
    user = session.get(User, row.user_id)
    if user is None or not user.active:
        return None
    row.last_used_at = utcnow()
    return user


def issue_api_token(
    session: Session, user: User, *, token_id: str, name: str, ttl_days: int | None
) -> tuple[ApiToken, str]:
    """A new personal token; the plaintext is returned once and never stored."""
    raw = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(
        id=token_id,
        user_id=user.id,
        name=name,
        token_hash=token_hash(raw),
        prefix=raw[: len(API_TOKEN_PREFIX) + 4],
        expires_at=utcnow() + timedelta(days=ttl_days) if ttl_days else None,
    )
    session.add(row)
    return row, raw


def revoke_token(session: Session, raw: str) -> bool:
    """Revoke ``raw``; True when it existed."""
    row = session.get(SessionToken, token_hash(raw))
    if row is None:
        return False
    row.revoked = True
    return True


def revoke_user_tokens(session: Session, user_id: str) -> int:
    """Revoke every token of a user (role change, deactivation, deletion)."""
    rows = session.scalars(select(SessionToken).where(SessionToken.user_id == user_id)).all()
    for row in rows:
        row.revoked = True
    personal = session.scalars(select(ApiToken).where(ApiToken.user_id == user_id)).all()
    for item in personal:
        item.revoked = True
    return len(rows) + len(personal)
