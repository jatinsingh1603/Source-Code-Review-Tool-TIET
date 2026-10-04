from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from codekavach.config import LoadedConfig, load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.models.finding import Finding
from codekavach.core.models.ids import new_finding_id, new_project_id, new_scan_id
from codekavach.core.models.scan import Scan
from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.core.pipeline.result import StageOutcome
from codekavach.core.pipeline.runner import ScanOutcome, run_scan
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.db import init_db, make_session_factory, session_scope
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.orm import ProjectRow, ScanRow, StageRunRow
from codekavach.core.store.repositories import (
    FindingRepository,
    ProjectRepository,
    ScanRecorder,
    ScanRepository,
)
from tests.support import fake_stages_module
from tests.support.factories import make_finding, make_project, make_scan
from tests.support.pipeline import FakeStage

SALT_HEX = "7e" * 32  # pragma: allowlist secret
HERE = "tests.integration.core.test_run_scan_persist"
FAKES = "tests.support.fake_stages_module"
FINDINGS = [
    make_finding(id=new_finding_id(), fingerprint=f"ckfp1:{index:032x}") for index in range(3)
]


def rate_three() -> FakeStage:
    return FakeStage(
        "rate",
        requires={"candidates"},
        provides={"findings"},
        category=StageCategory.RATE,
        writes={"findings": list(FINDINGS)},
    )


def ingest_broken() -> FakeStage:
    return FakeStage(
        "ingest",
        requires={"scan.target"},
        provides={"files", "languages"},
        category=StageCategory.INGEST,
        raises=RuntimeError("boom"),
    )


def registry(*, ingest: str = f"{FAKES}:ingest") -> PluginRegistry:
    targets = {
        "ingest": ingest,
        "analyse-fake": f"{FAKES}:analyse_fake",
        "aggregate": f"{FAKES}:aggregate",
        "rate": f"{HERE}:rate_three",
    }
    return PluginRegistry(
        [
            PluginSpec("codekavach.stages", name, target, "p", "1")
            for name, target in targets.items()
        ]
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    fake_stages_module.FAIL_ANALYSIS[0] = False
    return root


def loaded(repo: Path) -> LoadedConfig:
    return load_settings(target=repo, env={"CODEKAVACH_HOME": str(repo.parent / "home")})


def scan(repo: Path, **options: object) -> ScanOutcome:
    options.setdefault("registry", registry())
    return run_scan(loaded(repo), str(repo), salt=ScanSalt.from_hex(SALT_HEX), **options)  # type: ignore[arg-type]


def test_completed_scan_is_recorded(repo: Path) -> None:
    outcome = scan(repo)
    assert outcome.result.status is ScanStatus.COMPLETED
    engine = init_db(StateLayout(outcome.state_dir))
    try:
        with session_scope(make_session_factory(engine)) as session:
            projects = session.execute(select(ProjectRow)).scalars().all()
            assert [project.root for project in projects] == [str(loaded(repo).project_root)]
            assert [row.id for row in session.execute(select(ScanRow)).scalars()] == [
                outcome.scan.id
            ]
            assert ScanRepository(session).get(outcome.scan.id) == outcome.scan
            runs = session.execute(select(StageRunRow).order_by(StageRunRow.position)).scalars()
            assert [run.name for run in runs] == list(outcome.result.order)
            stored = FindingRepository(session).for_scan(outcome.scan.id)
            assert stored == sorted(FINDINGS, key=Finding.sort_key)
    finally:
        engine.dispose()
    database = (outcome.state_dir / "codekavach.db").read_bytes()
    assert SALT_HEX.encode() not in database
    assert bytes.fromhex(SALT_HEX) not in database


def test_second_scan_reuses_the_project_and_cached_findings(repo: Path) -> None:
    first = scan(repo)
    second = scan(repo)
    rate = second.result.run_of("rate")
    assert rate is not None
    assert rate.outcome is StageOutcome.CACHED
    assert second.scan.project_id == first.scan.project_id
    engine = init_db(StateLayout(second.state_dir))
    try:
        with session_scope(make_session_factory(engine)) as session:
            assert len(session.execute(select(ProjectRow)).all()) == 1
            scans = ScanRepository(session).list(first.scan.project_id)
            assert {item.id for item in scans} == {first.scan.id, second.scan.id}
            findings = FindingRepository(session)
            assert len(findings.for_scan(first.scan.id)) == 3
            assert len(findings.for_scan(second.scan.id)) == 3
            assert len(findings.by_fingerprint(first.scan.project_id, FINDINGS[0].fingerprint)) == 2
    finally:
        engine.dispose()


def stored_statuses(state_dir: Path) -> dict[str, str]:
    engine = init_db(StateLayout(state_dir))
    try:
        with session_scope(make_session_factory(engine)) as session:
            return {row.id: row.status for row in session.execute(select(ScanRow)).scalars()}
    finally:
        engine.dispose()


def test_other_outcomes_are_recorded(repo: Path) -> None:
    fake_stages_module.FAIL_ANALYSIS[0] = True
    with_errors = scan(repo)
    fake_stages_module.FAIL_ANALYSIS[0] = False
    failed = scan(repo, registry=registry(ingest=f"{HERE}:ingest_broken"))
    token = CancellationToken()
    token.cancel()
    cancelled = scan(repo, cancellation=token)
    assert stored_statuses(cancelled.state_dir) == {
        with_errors.scan.id: "completed_with_errors",
        failed.scan.id: "failed",
        cancelled.scan.id: "cancelled",
    }
    engine = init_db(StateLayout(failed.state_dir))
    try:
        with session_scope(make_session_factory(engine)) as session:
            assert ScanRepository(session).get(failed.scan.id) == failed.scan
            assert FindingRepository(session).for_scan(failed.scan.id) == []
    finally:
        engine.dispose()


def test_persist_false_leaves_no_database(repo: Path) -> None:
    outcome = scan(repo, persist=False)
    assert outcome.result.status is ScanStatus.COMPLETED
    assert not list(outcome.state_dir.rglob("codekavach.db*"))


def test_stale_running_scan_is_failed_by_the_next_scan(repo: Path) -> None:
    config = loaded(repo)
    now = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
    timeout = timedelta(seconds=config.settings.scan.timeout_seconds)
    project = make_project(id=new_project_id(), root=str(config.project_root))
    old = make_scan(
        id=new_scan_id(),
        project_id=project.id,
        status=ScanStatus.RUNNING,
        started_at=now - timeout - timedelta(minutes=1),
        finished_at=None,
        summary=None,
    )
    young = old.evolve(id=new_scan_id(), started_at=now - timedelta(minutes=1))
    state_dir = scan(repo, persist=False).state_dir
    recorder = ScanRecorder(StateLayout(state_dir))
    for running in (old, young):
        recorder.start(project, running, stale_before=old.started_at, now=old.started_at)
    outcome = scan(repo, clock=lambda: now)
    assert outcome.scan.project_id == project.id
    assert stored_statuses(state_dir) == {
        old.id: "failed",
        young.id: "running",
        outcome.scan.id: "completed",
    }
    engine = init_db(StateLayout(state_dir))
    try:
        with session_scope(make_session_factory(engine)) as session:
            assert ProjectRepository(session).get_by_root(str(config.project_root)) == project
            assert ScanRepository(session).get(young.id) == Scan.model_validate(young.model_dump())
    finally:
        engine.dispose()
