"""Passwords, tokens, the permission matrix, the audit chain and the event log."""

from datetime import timedelta
from pathlib import Path

import pytest

from codekavach.server import audit
from codekavach.server.auth.passwords import hash_password, needs_rehash, verify_password
from codekavach.server.auth.tokens import authenticate_token, issue_token, revoke_token
from codekavach.server.db.engine import Database
from codekavach.server.db.models import AuditEvent, SessionToken, User, utcnow
from codekavach.server.events import EventLog
from codekavach.server.rbac import Permission, Role, permitted
from codekavach.server.state import RateLimiter

pytest.importorskip("fastapi")


def test_password_round_trip() -> None:
    stored = hash_password("correct horse")
    assert stored.startswith("scrypt$")
    assert "correct horse" not in stored
    assert verify_password("correct horse", stored)
    assert not verify_password("wrong", stored)
    assert not verify_password("x", "garbage")
    assert not needs_rehash(stored)
    assert needs_rehash("scrypt$1024$8$1$00$00")


def test_tokens_store_only_a_hash_and_stop_after_revocation(tmp_path: Path) -> None:
    db = Database(tmp_path / "s.db")
    with db.transaction() as session:
        user = User(id="usr_1", username="a", role="viewer", password_hash="x")
        session.add(user)
        session.flush()
        raw = issue_token(session, user, 60)
    with db.transaction() as session:
        stored = session.query(SessionToken).one()
        assert raw not in stored.token_hash
        assert authenticate_token(session, raw) is not None
        assert authenticate_token(session, raw + "x") is None
        revoke_token(session, raw)
    with db.transaction() as session:
        assert authenticate_token(session, raw) is None


def test_expired_tokens_fail(tmp_path: Path) -> None:
    db = Database(tmp_path / "s.db")
    with db.transaction() as session:
        user = User(id="usr_1", username="a", role="viewer", password_hash="x")
        session.add(user)
        session.flush()
        raw = issue_token(session, user, 60)
        session.flush()
        session.query(SessionToken).one().expires_at = utcnow() - timedelta(seconds=1)
    with db.transaction() as session:
        assert authenticate_token(session, raw) is None


@pytest.mark.parametrize(
    ("role", "permission", "allowed"),
    [
        (Role.viewer, Permission.read, True),
        (Role.viewer, Permission.scan_run, False),
        (Role.viewer, Permission.ledger_read, False),
        (Role.developer, Permission.scan_run, True),
        (Role.developer, Permission.original_read, False),
        (Role.auditor, Permission.original_read, True),
        (Role.auditor, Permission.users_admin, False),
        (Role.admin, Permission.users_admin, True),
    ],
)
def test_permission_matrix(role: Role, permission: Permission, allowed: bool) -> None:
    assert permitted(role, permission) is allowed
    assert permitted("nobody", permission) is False


def test_audit_chain_detects_an_edit(tmp_path: Path) -> None:
    db = Database(tmp_path / "s.db")
    for index in range(3):
        audit.record(db, actor="a", action=f"act{index}")
    audit.flush(db)
    with db.transaction() as session:
        assert audit.verify_audit_chain(session) == (True, 3)
        session.query(AuditEvent).filter(AuditEvent.action == "act1").one().actor = "mallory"
    with db.transaction() as session:
        assert audit.verify_audit_chain(session)[0] is False


def test_rate_limiter() -> None:
    now = [0.0]
    limiter = RateLimiter(2, clock=lambda: now[0])
    assert limiter.hit("k") is None
    assert limiter.hit("k") is None
    assert limiter.hit("k") is not None
    now[0] = 61.0
    assert limiter.hit("k") is None


def test_event_log_persists_and_resumes(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    log = EventLog(path)
    log.append("stage", {"name": "parse", "status": "running"})
    log.append("progress", {"percent": 10, "message": "x"})
    log.append("done", {"status": "completed"})
    assert [event.id for event in log.since(1)] == [2, 3]
    reopened = EventLog(path)
    assert reopened.closed
    assert [event.type for event in reopened.all()] == ["stage", "progress", "done"]
    assert reopened.all()[0].frame().startswith("id: 1\nevent: stage\ndata: ")
    with pytest.raises(ValueError, match="unknown event type"):
        log.append("scan.started", {})
