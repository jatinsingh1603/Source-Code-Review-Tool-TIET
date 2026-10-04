"""Repositories of the local database: the only code that reads and writes its tables (E04-27).

Owning epic: E04.

Each repository is constructed with a ``Session`` and converts between E02 models and rows.
``document_json`` (``model_dump_json()``) is authoritative: models are rebuilt from it with
``load_versioned`` and never from the scalar columns, which exist for filtering and sorting.
Repositories do not commit; the caller's ``session_scope`` does, so a failing call rolls back.

The rows hold restored findings (real paths and evidence text), which is confidential client data;
it stays in the local database and this module offers no export. No model stored here contains the
scan salt or vault contents (I3). Errors are logged by exception class only: SQL parameters contain
finding text and the engine hides them (``hide_parameters=True``).
"""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from pydantic import JsonValue
from sqlalchemy import delete, func, insert, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from codekavach.core.log import get_logger
from codekavach.core.models.enums import FindingStatus, ScanStatus, Severity
from codekavach.core.models.finding import Finding
from codekavach.core.models.migrate import load_versioned
from codekavach.core.models.scan import Project, Scan
from codekavach.core.pipeline.errors import PersistenceError
from codekavach.core.pipeline.result import StageRun
from codekavach.core.store.db import (
    create_db_engine,
    init_db,
    make_session_factory,
    session_scope,
    sqlite_url,
)
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.migrate import current_revision, head_revision
from codekavach.core.store.orm import Base, FindingRow, ProjectRow, ScanRow, StageRunRow

INSERT_CHUNK = 500
_RULE_ID_LENGTH = 200
_log = get_logger("codekavach.store.repositories")


def _project_values(project: Project) -> dict[str, object]:
    return {
        "id": project.id,
        "name": project.name,
        "root": project.root,
        "repository_url": project.repository_url,
        "created_at": project.created_at,
        "document_json": project.model_dump_json(),
    }


def _scan_values(scan: Scan) -> dict[str, object]:
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status.value,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "codekavach_version": scan.codekavach_version,
        "config_hash": scan.config_hash,
        "privacy_level": scan.privacy_level.value,
        "findings_total": scan.summary.findings_total if scan.summary is not None else None,
        "document_json": scan.model_dump_json(),
    }


def _finding_values(scan_id: str, finding: Finding) -> dict[str, object]:
    primary = finding.primary_location
    engines = finding.provenance.engines
    return {
        "id": finding.id,
        "scan_id": scan_id,
        "fingerprint": finding.fingerprint,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "cwe": finding.primary_cwe,
        "rule_id": engines[0].rule_id[:_RULE_ID_LENGTH] if engines else None,
        "primary_path": primary.path,
        "primary_line": primary.start_line,
        "title": finding.title,
        "document_json": finding.model_dump_json(),
    }


class ProjectRepository:
    """Projects by id or by root directory."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, project_id: str) -> Project | None:
        """The project with ``project_id``, or ``None``."""
        row = self._session.get(ProjectRow, project_id)
        return None if row is None else load_versioned(Project, row.document_json)

    def get_by_root(self, root: str) -> Project | None:
        """The oldest project recorded for the directory ``root``, or ``None``."""
        row = self._session.execute(
            select(ProjectRow)
            .where(ProjectRow.root == root)
            .order_by(ProjectRow.created_at, ProjectRow.id)
            .limit(1)
        ).scalar_one_or_none()
        return None if row is None else load_versioned(Project, row.document_json)

    def upsert(self, project: Project) -> None:
        """Insert ``project`` or replace the stored one with the same id."""
        self._session.merge(ProjectRow(**_project_values(project)))
        self._session.flush()


class FindingRepository:
    """Findings of scans."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def replace_for_scan(self, scan_id: str, findings: Sequence[Finding]) -> None:
        """Replace the findings of ``scan_id`` with ``findings``, in chunks of 500 rows.

        The delete and the inserts belong to the caller's transaction: when an insert fails
        (``IntegrityError`` for a repeated fingerprint), rolling back keeps the previous rows.
        """
        self._session.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
        rows = [_finding_values(scan_id, finding) for finding in findings]
        for start in range(0, len(rows), INSERT_CHUNK):
            self._session.execute(insert(FindingRow), rows[start : start + INSERT_CHUNK])

    def for_scan(
        self,
        scan_id: str,
        *,
        min_severity: Severity | None = None,
        status: FindingStatus | None = None,
        cwe: int | None = None,
    ) -> list[Finding]:
        """Findings of ``scan_id`` in report order (``Finding.sort_key``).

        ``min_severity`` compares by the rank of ``Severity``; ``cwe`` matches the primary CWE.
        """
        query = select(FindingRow.document_json).where(FindingRow.scan_id == scan_id)
        if min_severity is not None:
            wanted = [member.value for member in Severity if member.rank >= min_severity.rank]
            query = query.where(FindingRow.severity.in_(wanted))
        if status is not None:
            query = query.where(FindingRow.status == status.value)
        if cwe is not None:
            query = query.where(FindingRow.cwe == cwe)
        documents = self._session.execute(query).scalars().all()
        return sorted(
            (load_versioned(Finding, document) for document in documents),
            key=lambda finding: finding.sort_key(),
        )

    def by_fingerprint(self, project_id: str, fingerprint: str) -> list[Finding]:
        """Findings with ``fingerprint`` across the scans of a project, newest scan first."""
        documents = self._session.execute(
            select(FindingRow.document_json)
            .join(ScanRow, ScanRow.id == FindingRow.scan_id)
            .where(ScanRow.project_id == project_id, FindingRow.fingerprint == fingerprint)
            .order_by(ScanRow.started_at.desc(), ScanRow.id.desc())
        ).scalars()
        return [load_versioned(Finding, document) for document in documents]

    def count_by_severity(self, scan_id: str) -> dict[Severity, int]:
        """How many findings of ``scan_id`` have each severity that occurs."""
        counts = self._session.execute(
            select(FindingRow.severity, func.count())
            .where(FindingRow.scan_id == scan_id)
            .group_by(FindingRow.severity)
        ).all()
        return {Severity(severity): count for severity, count in counts}


class ScanRepository:
    """Scans and their stage runs."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, scan: Scan) -> None:
        """Insert ``scan``."""
        self._session.add(ScanRow(**_scan_values(scan)))
        self._session.flush()

    def update(self, scan: Scan) -> None:
        """Replace the stored scan with the same id.

        Raises:
            LookupError: no scan with that id is stored.
        """
        row = self._session.get(ScanRow, scan.id)
        if row is None:
            raise LookupError(f"scan {scan.id!r} is not stored")
        for name, value in _scan_values(scan).items():
            setattr(row, name, value)
        self._session.flush()

    def get(self, scan_id: str) -> Scan | None:
        """The scan with ``scan_id``, or ``None``."""
        document = self._session.execute(
            select(ScanRow.document_json).where(ScanRow.id == scan_id)
        ).scalar_one_or_none()
        return None if document is None else load_versioned(Scan, document)

    def latest(
        self, project_id: str, *, statuses: frozenset[ScanStatus] | set[ScanStatus] | None = None
    ) -> Scan | None:
        """The newest scan of a project, optionally among ``statuses`` only."""
        query = select(ScanRow.document_json).where(ScanRow.project_id == project_id)
        if statuses is not None:
            query = query.where(ScanRow.status.in_(sorted(status.value for status in statuses)))
        document = self._session.execute(
            query.order_by(ScanRow.started_at.desc(), ScanRow.id.desc()).limit(1)
        ).scalar_one_or_none()
        return None if document is None else load_versioned(Scan, document)

    def running_before(self, project_id: str, started_before: datetime) -> Sequence[Scan]:
        """Scans of a project still ``running`` that started before ``started_before``."""
        documents = self._session.execute(
            select(ScanRow.document_json)
            .where(
                ScanRow.project_id == project_id,
                ScanRow.status == ScanStatus.RUNNING.value,
                ScanRow.started_at < started_before,
            )
            .order_by(ScanRow.started_at, ScanRow.id)
        ).scalars()
        return [load_versioned(Scan, document) for document in documents]

    def set_stage_runs(self, scan_id: str, runs: Sequence[StageRun]) -> None:
        """Replace the stage runs of ``scan_id`` with ``runs``, keeping their order."""
        self._session.execute(delete(StageRunRow).where(StageRunRow.scan_id == scan_id))
        rows = [
            {
                "scan_id": scan_id,
                "position": position,
                "name": run.stage,
                "outcome": run.outcome.value,
                "duration_ms": run.duration_ms,
                "error_code": run.error_code,
                "error_type": run.error_type,
                "skip_reason": run.skip_reason,
            }
            for position, run in enumerate(runs)
        ]
        if rows:
            self._session.execute(insert(StageRunRow), rows)

    def delete(self, scan_id: str) -> None:
        """Delete a scan with its stage runs and findings."""
        self._session.execute(delete(ScanRow).where(ScanRow.id == scan_id))

    def list(self, project_id: str, *, limit: int = 50, offset: int = 0) -> Sequence[Scan]:
        """Scans of a project, newest first."""
        documents = self._session.execute(
            select(ScanRow.document_json)
            .where(ScanRow.project_id == project_id)
            .order_by(ScanRow.started_at.desc(), ScanRow.id.desc())
            .limit(limit)
            .offset(offset)
        ).scalars()
        return [load_versioned(Scan, document) for document in documents]


class ScanRecorder:
    """What ``run_scan`` persists: the start record, then the final record.

    Each call opens the database, runs one transaction and closes it again, so that no
    transaction and no file handle stays open while the scan runs. Database errors are logged by
    exception class and raised as ``PersistenceError``.
    """

    def __init__(self, layout: StateLayout) -> None:
        self._layout = layout

    @contextmanager
    def _session(self, step: str) -> Iterator[Session]:
        try:
            engine = init_db(self._layout)
            try:
                with session_scope(make_session_factory(engine)) as session:
                    yield session
            finally:
                engine.dispose()
        except SQLAlchemyError as error:
            _log.error("scan_persist_failed", step=step, error_type=type(error).__name__)
            raise PersistenceError(step, type(error).__name__) from error

    def project_by_root(self, root: str) -> Project | None:
        """The project recorded for the directory ``root``, or ``None``."""
        with self._session("project") as session:
            return ProjectRepository(session).get_by_root(root)

    def start(self, project: Project, scan: Scan, *, stale_before: datetime, now: datetime) -> Scan:
        """Store ``project`` and the running ``scan``; returns the scan as stored.

        Scans of the project still ``running`` that started before ``stale_before`` were left
        behind by a process that died; they are marked ``failed``. Younger ones may belong to a
        scan running at the same time and are left alone.

        A scan id that is already stored is a resumed scan (E04-28): its row is updated instead
        of inserted, and ``started_at`` and the project stay those of the first attempt.
        """
        with self._session("start") as session:
            scans = ScanRepository(session)
            earlier = scans.get(scan.id)
            if earlier is None:
                ProjectRepository(session).upsert(project)
            for stale in scans.running_before(project.id, stale_before):
                if stale.id == scan.id:
                    continue
                scans.update(stale.finish(ScanStatus.FAILED, None, max(now, stale.started_at)))
                _log.warning("stale_scan_marked_failed", scan_id=stale.id)
            if earlier is None:
                scans.add(scan)
                return scan
            resumed = scan.evolve(started_at=earlier.started_at, project_id=earlier.project_id)
            scans.update(resumed)
            return resumed

    def finish(
        self, scan: Scan, runs: Sequence[StageRun], findings: Sequence[Finding] | None
    ) -> None:
        """Store the final ``scan``, its stage runs and, when given, its findings."""
        with self._session("finish") as session:
            scans = ScanRepository(session)
            scans.update(scan)
            scans.set_stage_runs(scan.id, runs)
            if findings is not None:
                FindingRepository(session).replace_for_scan(scan.id, findings)

    def abort(self, scan_id: str, status: ScanStatus, at: datetime) -> None:
        """Mark a running scan as ended with ``status`` when the orchestrator raised."""
        with self._session("abort") as session:
            scans = ScanRepository(session)
            scan = scans.get(scan_id)
            if scan is not None and scan.finished_at is None:
                scans.update(scan.finish(status, None, max(at, scan.started_at)))


FINISHED_STATUSES = frozenset({ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS})


class StoredScanLookup:
    """Read-only access to the stored scans of one state directory, for reports (E05-15).

    Nothing is created: without a database every lookup finds nothing. Each call opens the
    database, reads and closes it again.
    """

    def __init__(self, layout: StateLayout) -> None:
        self._layout = layout

    @contextmanager
    def _session(self) -> Iterator[Session | None]:
        if not self._layout.db_path.is_file():
            yield None
            return
        engine = init_db(self._layout)
        try:
            with session_scope(make_session_factory(engine)) as session:
                yield session
        finally:
            engine.dispose()

    def latest(self, project_root: Path) -> Scan | None:
        """The newest finished scan of the project at ``project_root``; others are skipped."""
        with self._session() as session:
            if session is None:
                return None
            project = ProjectRepository(session).get_by_root(str(project_root))
            if project is None:
                return None
            return ScanRepository(session).latest(project.id, statuses=FINISHED_STATUSES)

    def get(self, scan_id: str) -> Scan | None:
        """The scan with ``scan_id``, or ``None``."""
        with self._session() as session:
            return None if session is None else ScanRepository(session).get(scan_id)

    def findings(self, scan_id: str) -> Sequence[Finding] | None:
        """The findings of a finished scan; ``None`` when the scan is unknown or did not finish."""
        with self._session() as session:
            if session is None:
                return None
            scan = ScanRepository(session).get(scan_id)
            if scan is None or scan.status not in FINISHED_STATUSES:
                return None
            return FindingRepository(session).for_scan(scan_id)


def open_scan_lookup(state_dir: Path) -> StoredScanLookup:
    """The lookup over the local database below ``state_dir``."""
    return StoredScanLookup(StateLayout(state_dir))


def db_probe(layout: StateLayout) -> dict[str, JsonValue]:
    """Facts about the local database for ``codekavach doctor``; creates and changes nothing."""
    path = layout.db_path
    probe: dict[str, JsonValue] = {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
        "revision": None,
        "head": head_revision(),
        "rows": {},
    }
    if not path.is_file():
        return probe
    engine = create_db_engine(sqlite_url(path))
    try:
        probe["revision"] = current_revision(engine)
        present = set(inspect(engine).get_table_names())
        with engine.connect() as connection:
            probe["rows"] = {
                table.name: connection.execute(select(func.count()).select_from(table)).scalar_one()
                for table in Base.metadata.sorted_tables
                if table.name in present
            }
    finally:
        engine.dispose()
    return probe
