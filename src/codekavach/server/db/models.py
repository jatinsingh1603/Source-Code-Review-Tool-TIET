"""Tables of the REST API server: users, tokens, projects, scans, triage state, settings, audit.

Owning epic: E32.

The server keeps its own SQLite database (``<data_dir>/server.db``) on a declarative base of its
own, so the CLI's local store and its Alembic chain are untouched; the tables are created with
``metadata.create_all`` at start-up. Findings are stored as the JSON of the core ``Finding`` model
plus the columns the list view filters on; triage state (status, assignee, history) is the
server's own. No table holds a provider key, a vault mapping or ledger payload text: payloads stay
encrypted in the scan's ledger and are decrypted only on an authorised read.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """The current time in UTC (naive values are never stored)."""
    return datetime.now(UTC)


class ServerBase(DeclarativeBase):
    """Declarative base of the server tables."""

    type_annotation_map: dict[Any, Any] = {dict[str, Any]: JSON, list[Any]: JSON}  # noqa: RUF012


class User(ServerBase):
    """A local account."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(256), default="")
    role: Mapped[str] = mapped_column(String(16))
    password_hash: Mapped[str] = mapped_column(String(256))
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(default=None)


class SessionToken(ServerBase):
    """An opaque bearer token; only its SHA-256 is stored."""

    __tablename__ = "session_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    revoked: Mapped[bool] = mapped_column(default=False)


class Project(ServerBase):
    """A code base the server scans."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    source_type: Mapped[str] = mapped_column(String(16))
    source_path: Mapped[str | None] = mapped_column(Text, default=None)
    source_url: Mapped[str | None] = mapped_column(Text, default=None)
    source_ref: Mapped[str | None] = mapped_column(String(256), default=None)
    upload_name: Mapped[str | None] = mapped_column(String(256), default=None)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)


class ScanRow(ServerBase):
    """One scan job and its outcome."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    stage: Mapped[str | None] = mapped_column(String(64), default=None)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    privacy_level: Mapped[str] = mapped_column(String(4), default="L2")
    provider: Mapped[str] = mapped_column(String(64), default="mock")
    model: Mapped[str | None] = mapped_column(String(128), default=None)
    send: Mapped[bool] = mapped_column(default=False)
    rules: Mapped[list[Any]] = mapped_column(default=list)
    counts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    files: Mapped[int] = mapped_column(Integer, default=0)
    lines: Mapped[int] = mapped_column(Integer, default=0)
    languages: Mapped[list[Any]] = mapped_column(default=list)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    core_scan_id: Mapped[str | None] = mapped_column(String(64), default=None)
    workspace: Mapped[str | None] = mapped_column(Text, default=None)
    state_dir: Mapped[str | None] = mapped_column(Text, default=None)
    privacy: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_by: Mapped[str | None] = mapped_column(String(40), default=None)
    triage_updated_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (Index("ix_scans_project", "project_id"),)


class FindingRow(ServerBase):
    """One finding of one scan, with its server-side triage state."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    severity_rank: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    cwe: Mapped[str] = mapped_column(String(128), default="")
    path: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int] = mapped_column(Integer, default=0)
    rule_id: Mapped[str] = mapped_column(String(128), default="")
    engine: Mapped[str] = mapped_column(String(64), default="")
    fingerprint: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(24), default="open")
    assignee: Mapped[str | None] = mapped_column(String(64), default=None)
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow)

    __table_args__ = (Index("ix_findings_scan", "scan_id"),)


class FindingEvent(ServerBase):
    """A triage change or comment on a finding (append-only)."""

    __tablename__ = "finding_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    at: Mapped[datetime] = mapped_column(default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    from_status: Mapped[str | None] = mapped_column(String(24), default=None)
    to_status: Mapped[str | None] = mapped_column(String(24), default=None)
    assignee: Mapped[str | None] = mapped_column(String(64), default=None)
    comment: Mapped[str | None] = mapped_column(Text, default=None)


class SettingRow(ServerBase):
    """A server setting (JSON value)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(default=dict)


class AuditEvent(ServerBase):
    """A security-relevant action, allowed or denied, hash-chained to the previous one."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    resource: Mapped[str] = mapped_column(String(128), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="allowed")
    client: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="")
