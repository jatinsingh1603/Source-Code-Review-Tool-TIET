"""A scan left running by a stopped server is failed at start-up, in words a person can act on."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("sqlalchemy")

from codekavach.server.db.engine import Database
from codekavach.server.db.models import Project, ScanRow, utcnow
from codekavach.server.jobs.runner import RESTARTED_MESSAGE, JobRunner


class _Log:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def append(self, kind: str, data: dict[str, Any]) -> None:
        self.events.append((kind, data))


def test_recover_fails_orphaned_scans_in_words(tmp_path: Path) -> None:
    db = Database(tmp_path / "server.db")
    with db.transaction() as session:
        session.add(Project(id="prj_a", name="A", source_type="sample"))
        session.flush()
        now = utcnow()
        session.add(ScanRow(id="scn_run", project_id="prj_a", status="running", started_at=now))
        session.add(ScanRow(id="scn_done", project_id="prj_a", status="completed", started_at=now))
    logs: dict[str, _Log] = {}
    hub = SimpleNamespace(log=lambda scan_id: logs.setdefault(scan_id, _Log()))
    state: Any = SimpleNamespace(db=db, hub=hub)
    jobs = JobRunner(state, workers=1)
    try:
        assert jobs.recover() == 1
    finally:
        jobs.shutdown(timeout=1)
    with db.transaction() as session:
        run = session.get(ScanRow, "scn_run")
        done = session.get(ScanRow, "scn_done")
        assert run is not None and done is not None
        assert run.status == "failed"
        assert run.error == RESTARTED_MESSAGE
        assert done.status == "completed"
    assert not RESTARTED_MESSAGE.startswith("server_restarted")
    assert logs["scn_run"].events == [("done", {"status": "failed", "error": "server_restarted"})]
    db.dispose()
