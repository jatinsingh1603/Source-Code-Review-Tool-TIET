from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from codekavach.core.models.enums import FindingStatus, ScanStatus, Severity
from codekavach.core.models.finding import Finding
from codekavach.core.models.ids import new_finding_id, new_project_id, new_scan_id
from codekavach.core.models.scan import Project, Scan
from codekavach.core.pipeline.errors import PersistenceError
from codekavach.core.pipeline.result import StageOutcome, StageRun
from codekavach.core.store.db import (
    create_db_engine,
    init_db,
    make_session_factory,
    session_scope,
)
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.migrate import head_revision, upgrade_to_head
from codekavach.core.store.orm import FindingRow, StageRunRow
from codekavach.core.store.repositories import (
    FindingRepository,
    ProjectRepository,
    ScanRecorder,
    ScanRepository,
    db_probe,
)
from tests.support import strategies
from tests.support.factories import FIXED_NOW, make_finding, make_project, make_scan, make_summary

MEMORY_URL = "sqlite+pysqlite:///:memory:"


@contextmanager
def memory_sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_db_engine(MEMORY_URL)
    try:
        upgrade_to_head(engine)
        yield make_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    with memory_sessions() as sessions:
        yield sessions


def scan_with(status: ScanStatus, **overrides: object) -> Scan:
    ended = status not in (ScanStatus.PENDING, ScanStatus.RUNNING)
    completed = status in (ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS)
    started_at = overrides.get("started_at", FIXED_NOW)
    assert isinstance(started_at, datetime)
    values: dict[str, object] = {
        "id": new_scan_id(),
        "status": status,
        "finished_at": started_at + timedelta(seconds=4) if ended else None,
        "summary": make_summary() if completed else None,
    }
    return make_scan(**{**values, **overrides})


def finding_with(index: int, **overrides: object) -> Finding:
    values: dict[str, object] = {"id": new_finding_id(), "fingerprint": f"ckfp1:{index:032x}"}
    return make_finding(**{**values, **overrides})


def seed(session: Session, *scans: Scan) -> None:
    ProjectRepository(session).upsert(make_project())
    for scan in scans:
        ScanRepository(session).add(scan)


def test_project_round_trip_root_and_upsert(factory: sessionmaker[Session]) -> None:
    project = make_project(root="/work/bank")
    with session_scope(factory) as session:
        projects = ProjectRepository(session)
        projects.upsert(project)
        assert projects.get(project.id) == project
        assert projects.get_by_root("/work/bank") == project
        assert projects.get_by_root("/work/other") is None
        assert projects.get(new_project_id()) is None
        renamed = project.evolve(name="KavachBank 2")
        projects.upsert(renamed)
        assert projects.get(project.id) == renamed


@pytest.mark.parametrize("status", list(ScanStatus))
def test_scan_round_trip_in_every_status(
    factory: sessionmaker[Session], status: ScanStatus
) -> None:
    scan = scan_with(status)
    with session_scope(factory) as session:
        seed(session, scan)
        assert ScanRepository(session).get(scan.id) == scan


def test_finding_round_trip_with_taint_path_and_evidence(factory: sessionmaker[Session]) -> None:
    scan = scan_with(ScanStatus.COMPLETED)
    finding = make_finding()
    assert finding.taint_path is not None
    assert finding.evidence
    with session_scope(factory) as session:
        seed(session, scan)
        findings = FindingRepository(session)
        findings.replace_for_scan(scan.id, [finding])
        assert findings.for_scan(scan.id) == [finding]
        row = session.execute(select(FindingRow)).scalar_one()
        primary = finding.primary_location
        assert (row.primary_path, row.primary_line) == (primary.path, primary.start_line)
        assert (row.cwe, row.rule_id) == (89, finding.provenance.engines[0].rule_id)


def test_scan_update_latest_list_and_delete(factory: sessionmaker[Session]) -> None:
    running = scan_with(ScanStatus.RUNNING, started_at=FIXED_NOW + timedelta(hours=2))
    old = scan_with(ScanStatus.COMPLETED, started_at=FIXED_NOW - timedelta(hours=1))
    failed = scan_with(ScanStatus.FAILED, started_at=FIXED_NOW)
    with session_scope(factory) as session:
        seed(session, old, running, failed)
        scans = ScanRepository(session)
        project_id = old.project_id
        assert scans.latest(project_id) == running
        assert scans.latest(project_id, statuses={ScanStatus.COMPLETED}) == old
        assert scans.latest(project_id, statuses={ScanStatus.CANCELLED}) is None
        assert scans.latest(new_project_id()) is None
        assert list(scans.list(project_id)) == [running, failed, old]
        assert list(scans.list(project_id, limit=1, offset=1)) == [failed]
        ended = running.finish(ScanStatus.CANCELLED, None, FIXED_NOW + timedelta(hours=3))
        scans.update(ended)
        assert scans.get(running.id) == ended
        with pytest.raises(LookupError):
            scans.update(scan_with(ScanStatus.RUNNING))
        FindingRepository(session).replace_for_scan(old.id, [finding_with(1)])
        scans.set_stage_runs(old.id, [StageRun("ingest", StageOutcome.SUCCEEDED)])
        scans.delete(old.id)
        assert scans.get(old.id) is None
        assert session.execute(select(FindingRow)).all() == []
        assert session.execute(select(StageRunRow)).all() == []


def test_stage_runs_are_replaced_in_order(factory: sessionmaker[Session]) -> None:
    scan = scan_with(ScanStatus.COMPLETED_WITH_ERRORS)
    runs = [
        StageRun("ingest", StageOutcome.SUCCEEDED, duration_ms=12),
        StageRun("analyse", StageOutcome.FAILED, error_code="stage_exception", error_type="Boom"),
        StageRun("aggregate", StageOutcome.SKIPPED, skip_reason="upstream_failed"),
    ]
    with session_scope(factory) as session:
        seed(session, scan)
        scans = ScanRepository(session)
        scans.set_stage_runs(scan.id, [StageRun("old", StageOutcome.SUCCEEDED)])
        scans.set_stage_runs(scan.id, runs)
        rows = session.execute(select(StageRunRow).order_by(StageRunRow.position)).scalars().all()
        assert [(row.name, row.outcome) for row in rows] == [
            ("ingest", "succeeded"),
            ("analyse", "failed"),
            ("aggregate", "skipped"),
        ]
        assert (rows[0].duration_ms, rows[1].error_type, rows[2].skip_reason) == (
            12,
            "Boom",
            "upstream_failed",
        )


def test_finding_queries(factory: sessionmaker[Session]) -> None:
    scan = scan_with(ScanStatus.COMPLETED)
    stored = [
        finding_with(1, severity=Severity.CRITICAL),
        finding_with(2, severity=Severity.HIGH, cwe=(79,)),
        finding_with(3, severity=Severity.HIGH, status=FindingStatus.CONFIRMED),
        finding_with(4, severity=Severity.MEDIUM),
        finding_with(5, severity=Severity.INFO),
    ]
    with session_scope(factory) as session:
        seed(session, scan)
        findings = FindingRepository(session)
        findings.replace_for_scan(scan.id, stored)
        assert findings.for_scan(scan.id) == sorted(stored, key=Finding.sort_key)
        high = findings.for_scan(scan.id, min_severity=Severity.HIGH)
        assert {finding.id for finding in high} == {finding.id for finding in stored[:3]}
        assert findings.for_scan(scan.id, status=FindingStatus.CONFIRMED) == [stored[2]]
        assert findings.for_scan(scan.id, cwe=79) == [stored[1]]
        assert findings.for_scan(new_scan_id()) == []
        assert findings.count_by_severity(scan.id) == Counter(
            finding.severity for finding in stored
        )


def test_by_fingerprint_is_newest_scan_first(factory: sessionmaker[Session]) -> None:
    scans = [
        scan_with(ScanStatus.COMPLETED, started_at=FIXED_NOW + timedelta(days=offset))
        for offset in (0, 2, 1)
    ]
    with session_scope(factory) as session:
        seed(session, *scans)
        findings = FindingRepository(session)
        per_scan = {}
        for scan in scans:
            per_scan[scan.id] = finding_with(7)
            findings.replace_for_scan(scan.id, [per_scan[scan.id], finding_with(8)])
        found = findings.by_fingerprint(scans[0].project_id, f"ckfp1:{7:032x}")
        assert found == [per_scan[scans[1].id], per_scan[scans[2].id], per_scan[scans[0].id]]
        assert findings.by_fingerprint(new_project_id(), f"ckfp1:{7:032x}") == []


def test_cached_findings_are_stored_under_each_scan(factory: sessionmaker[Session]) -> None:
    first, second = scan_with(ScanStatus.COMPLETED), scan_with(ScanStatus.COMPLETED)
    reused = [finding_with(1), finding_with(2)]
    with session_scope(factory) as session:
        seed(session, first, second)
        findings = FindingRepository(session)
        findings.replace_for_scan(first.id, reused)
        findings.replace_for_scan(second.id, reused)
        assert len(findings.for_scan(first.id)) == len(findings.for_scan(second.id)) == 2


def test_replace_for_scan_replaces_and_rolls_back(factory: sessionmaker[Session]) -> None:
    scan = scan_with(ScanStatus.COMPLETED)
    first = [finding_with(1), finding_with(2)]
    with session_scope(factory) as session:
        seed(session, scan)
        FindingRepository(session).replace_for_scan(scan.id, first)
        FindingRepository(session).replace_for_scan(scan.id, first)
        assert len(session.execute(select(FindingRow)).all()) == 2
    with pytest.raises(IntegrityError), session_scope(factory) as session:
        FindingRepository(session).replace_for_scan(scan.id, [finding_with(3), finding_with(3)])
    with session_scope(factory) as session:
        assert FindingRepository(session).for_scan(scan.id) == sorted(first, key=Finding.sort_key)


def test_large_replace_is_chunked(factory: sessionmaker[Session]) -> None:
    scan = scan_with(ScanStatus.COMPLETED)
    many = [finding_with(index) for index in range(1201)]
    with session_scope(factory) as session:
        seed(session, scan)
        findings = FindingRepository(session)
        findings.replace_for_scan(scan.id, many)
        assert findings.count_by_severity(scan.id) == {Severity.HIGH: 1201}


@settings(max_examples=25, deadline=None)
@given(scan=strategies.scans(), project=strategies.projects())
def test_scan_and_project_round_trip_property(scan: Scan, project: Project) -> None:
    owner = project.evolve(id=scan.project_id)
    with memory_sessions() as sessions, session_scope(sessions) as session:
        ProjectRepository(session).upsert(owner)
        ScanRepository(session).add(scan)
        assert ProjectRepository(session).get(owner.id) == owner
        assert ScanRepository(session).get(scan.id) == scan


@settings(max_examples=25, deadline=None)
@given(finding=strategies.findings())
def test_finding_round_trip_property(finding: Finding) -> None:
    scan = scan_with(ScanStatus.COMPLETED)
    with memory_sessions() as sessions, session_scope(sessions) as session:
        seed(session, scan)
        findings = FindingRepository(session)
        findings.replace_for_scan(scan.id, [finding])
        assert findings.for_scan(scan.id) == [finding]


@pytest.fixture
def layout(tmp_path: Path) -> StateLayout:
    return StateLayout(tmp_path / ".codekavach")


def stored_scan(layout: StateLayout, scan_id: str) -> Scan | None:
    engine = init_db(layout)
    try:
        with session_scope(make_session_factory(engine)) as session:
            return ScanRepository(session).get(scan_id)
    finally:
        engine.dispose()


def test_recorder_marks_only_stale_running_scans_failed(layout: StateLayout) -> None:
    recorder = ScanRecorder(layout)
    project = make_project(root="/work/bank")
    now = FIXED_NOW + timedelta(hours=5)
    timeout = timedelta(hours=1)
    stale = scan_with(ScanStatus.RUNNING, started_at=now - timeout - timedelta(seconds=1))
    young = scan_with(ScanStatus.RUNNING, started_at=now - timeout + timedelta(seconds=1))
    other_project = make_project(id=new_project_id(), root="/work/other")
    foreign = scan_with(ScanStatus.RUNNING, project_id=other_project.id, started_at=FIXED_NOW)
    recorder.start(project, stale, stale_before=stale.started_at, now=stale.started_at)
    recorder.start(project, young, stale_before=stale.started_at, now=young.started_at)
    recorder.start(other_project, foreign, stale_before=FIXED_NOW, now=FIXED_NOW)
    assert recorder.project_by_root("/work/bank") == project
    current = scan_with(ScanStatus.RUNNING, started_at=now)
    recorder.start(project, current, stale_before=now - timeout, now=now)
    failed = stored_scan(layout, stale.id)
    assert failed is not None
    assert (failed.status, failed.finished_at) == (ScanStatus.FAILED, now)
    assert stored_scan(layout, young.id) == young
    assert stored_scan(layout, foreign.id) == foreign
    assert stored_scan(layout, current.id) == current


def test_recorder_finish_and_abort(layout: StateLayout) -> None:
    recorder = ScanRecorder(layout)
    project = make_project()
    running = scan_with(ScanStatus.RUNNING)
    recorder.start(project, running, stale_before=FIXED_NOW, now=FIXED_NOW)
    final = running.finish(ScanStatus.COMPLETED, make_summary(), FIXED_NOW + timedelta(seconds=9))
    with pytest.raises(PersistenceError) as info:
        recorder.finish(final, [], [finding_with(1), finding_with(1)])
    assert (info.value.step, info.value.error_type) == ("finish", "IntegrityError")
    assert "ckfp1" not in str(info.value)
    assert stored_scan(layout, running.id) == running
    recorder.finish(final, [StageRun("ingest", StageOutcome.SUCCEEDED)], [finding_with(1)])
    assert stored_scan(layout, running.id) == final
    recorder.abort(running.id, ScanStatus.FAILED, FIXED_NOW + timedelta(seconds=20))
    assert stored_scan(layout, running.id) == final
    crashed = scan_with(ScanStatus.RUNNING)
    recorder.start(project, crashed, stale_before=FIXED_NOW, now=FIXED_NOW)
    recorder.abort(crashed.id, ScanStatus.CANCELLED, FIXED_NOW + timedelta(seconds=30))
    aborted = stored_scan(layout, crashed.id)
    assert aborted is not None
    assert aborted.status is ScanStatus.CANCELLED


def test_db_probe(layout: StateLayout) -> None:
    absent = db_probe(layout)
    assert (absent["exists"], absent["revision"], absent["rows"]) == (False, None, {})
    assert absent["head"] == head_revision()
    assert not layout.db_path.exists()
    recorder = ScanRecorder(layout)
    recorder.start(
        make_project(), scan_with(ScanStatus.RUNNING), stale_before=FIXED_NOW, now=FIXED_NOW
    )
    probe = db_probe(layout)
    assert probe["path"] == str(layout.db_path)
    assert probe["exists"] is True
    assert isinstance(probe["size_bytes"], int)
    assert probe["size_bytes"] > 0
    assert probe["revision"] == probe["head"] == head_revision()
    assert probe["rows"] == {"projects": 1, "scans": 1, "stage_runs": 0, "findings": 0}
