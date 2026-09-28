from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from codekavach.core.store.db import create_db_engine, make_session_factory, sqlite_url
from codekavach.core.store.orm import Base, FindingRow, ProjectRow, ScanRow, StageRunRow

NOW = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
PROJECT = "prj_01J8ZC3W6T5X0Q9V7R4M2N1K8P"  # pragma: allowlist secret
SCAN = "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P"  # pragma: allowlist secret


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    created = create_db_engine(sqlite_url(tmp_path / "codekavach.db"))
    Base.metadata.create_all(created)
    yield created
    created.dispose()


def project() -> ProjectRow:
    return ProjectRow(id=PROJECT, name="demo", created_at=NOW, document_json="{}")


def scan(scan_id: str = SCAN, started_at: datetime = NOW) -> ScanRow:
    return ScanRow(
        id=scan_id,
        project_id=PROJECT,
        status="completed",
        started_at=started_at,
        codekavach_version="0.1.0",
        config_hash="0" * 64,
        privacy_level="L3",
        document_json="{}",
    )


def finding(finding_id: str, fingerprint: str, scan_id: str = SCAN, title: str = "t") -> FindingRow:
    return FindingRow(
        id=finding_id,
        scan_id=scan_id,
        fingerprint=fingerprint,
        severity="high",
        status="open",
        title=title,
        document_json="{}",
    )


def test_foreign_keys_and_cascade(engine: Engine) -> None:
    factory = make_session_factory(engine)
    with factory() as session:
        session.add(project())
        session.add(scan())
        session.commit()
        session.add(StageRunRow(scan_id=SCAN, position=0, name="ingest", outcome="succeeded"))
        session.add(finding("fnd_1", "f" * 64))
        session.commit()
        session.execute(delete(ScanRow).where(ScanRow.id == SCAN))
        session.commit()
        assert session.execute(select(StageRunRow)).scalars().all() == []
        assert session.execute(select(FindingRow)).scalars().all() == []


def test_unknown_scan_is_an_integrity_error_without_parameters(engine: Engine) -> None:
    marker = "PLANTED-FINDING-TITLE"
    with Session(engine) as session:
        session.add(finding("fnd_1", "f" * 64, scan_id="scan_missing", title=marker))
        with pytest.raises(IntegrityError) as info:
            session.commit()
    assert marker not in str(info.value)


def test_unique_scan_fingerprint(engine: Engine) -> None:
    with Session(engine) as session:
        session.add_all([project(), scan()])
        session.commit()
        session.add_all([finding("fnd_1", "a" * 64), finding("fnd_2", "a" * 64)])
        with pytest.raises(IntegrityError):
            session.commit()


def test_utc_datetime_round_trip_and_rejection(engine: Engine) -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    local = datetime(2026, 10, 1, 15, 0, 0, 123456, tzinfo=ist)
    with Session(engine) as session:
        session.add_all([project(), scan(started_at=local)])
        session.commit()
        stored = session.execute(select(ScanRow.started_at)).scalar_one()
        assert stored == local
        assert stored.tzinfo is UTC
        session.add(scan("scan_other", started_at=datetime(2026, 10, 1)))  # noqa: DTZ001 - naive on purpose
        with pytest.raises(StatementError, match="naive datetimes"):
            session.commit()


def test_naming_convention() -> None:
    scans = Base.metadata.tables["scans"]
    index_names = {index.name for index in scans.indexes}
    assert "ix_scans_status" in index_names
    fk_names = {fk.name for fk in scans.foreign_key_constraints}
    assert fk_names == {"fk_scans_project_id_projects"}
