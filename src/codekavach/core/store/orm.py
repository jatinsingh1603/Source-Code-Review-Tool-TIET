"""ORM tables of the local database: projects, scans, stage runs and findings (E04-25).

Owning epic: E04.

``document_json`` holds ``model_dump_json()`` of the E02 model and is authoritative; the scalar
columns exist for filtering and sorting only. ``Text`` rather than a JSON type keeps the schema
identical on SQLite and PostgreSQL (server mode, E32). Datetimes are stored by ``UtcDateTime`` as
fixed-width ISO 8601 UTC strings, whose string order is time order; naive datetimes are rejected.
The constraint naming convention lets Alembic batch operations work on SQLite (E04-26).
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import ForeignKey, Integer, MetaData, String, Text, UniqueConstraint
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
_ID = 40
_TIMESTAMP = "%Y-%m-%dT%H:%M:%S.%fZ"


class UtcDateTime(TypeDecorator[datetime]):
    """A timezone-aware datetime stored as a fixed-width UTC string (``...Z``)."""

    impl = String(32)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> str | None:
        """Aware datetime to UTC text; a naive datetime is refused."""
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("naive datetimes are not stored; use a timezone-aware datetime")
        return value.astimezone(UTC).strftime(_TIMESTAMP)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        """UTC text back to an aware datetime."""
        if value is None:
            return None
        return datetime.strptime(str(value), _TIMESTAMP).replace(tzinfo=UTC)


class Base(DeclarativeBase):
    """Declarative base with the constraint naming convention."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class ProjectRow(Base):
    """A scanned project."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(_ID), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    root: Mapped[str | None] = mapped_column(Text, nullable=True)
    repository_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)
    document_json: Mapped[str] = mapped_column(Text)


class ScanRow(Base):
    """One scan of a project."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(_ID), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(_ID), ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(UtcDateTime, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    codekavach_version: Mapped[str] = mapped_column(String(64))
    config_hash: Mapped[str] = mapped_column(String(64))
    privacy_level: Mapped[str] = mapped_column(String(8))
    findings_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    document_json: Mapped[str] = mapped_column(Text)


class StageRunRow(Base):
    """How one stage of one scan ended."""

    __tablename__ = "stage_runs"
    __table_args__ = (UniqueConstraint("scan_id", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        String(_ID), ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(32))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    skip_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)


class FindingRow(Base):
    """One finding of one scan.

    The key is (``id``, ``scan_id``): a scan whose ``rate`` stage is served from the stage cache
    reuses the findings of an earlier scan, ids included, and stores them under its own scan id.
    """

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint"),)

    id: Mapped[str] = mapped_column(String(_ID), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(_ID), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32))
    cwe: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    rule_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    primary_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    primary_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(Text)
    document_json: Mapped[str] = mapped_column(Text)
