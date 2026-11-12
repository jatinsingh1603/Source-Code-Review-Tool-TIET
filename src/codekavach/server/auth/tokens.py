"""Opaque bearer tokens: issue, authenticate, revoke.

Owning epic: E32.

A token is ``ck_`` plus 32 random bytes in URL-safe base64. Only its SHA-256 is stored, so a copy
of the database does not yield a usable token. Tokens expire after the configured lifetime and
stop working as soon as they are revoked (logout) or their user is disabled.
"""

import hashlib
import secrets
from datetime import timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from codekavach.server.db.engine import as_utc
from codekavach.server.db.models import SessionToken, User, utcnow

TOKEN_PREFIX: Final = "ck_"  # noqa: S105 - a format prefix, not a secret


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
    return len(rows)
