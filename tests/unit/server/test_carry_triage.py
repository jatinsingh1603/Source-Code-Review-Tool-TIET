"""A re-scan keeps the reviewer's triage of unchanged findings (fixed ones open again)."""

from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from codekavach.server.db.engine import Database
from codekavach.server.db.models import FindingEvent, FindingRow, Project, ScanRow, utcnow
from codekavach.server.insights import carry_triage


def _finding(scan: str, fp: str, status: str = "open", assignee: str | None = None) -> FindingRow:
    return FindingRow(id=f"{scan}-{fp}", scan_id=scan, title=fp, severity="high",
                      fingerprint=fp, status=status, assignee=assignee)  # fmt: skip


def test_carry_triage_keeps_decisions_and_reopens_fixed(tmp_path: Path) -> None:
    db = Database(tmp_path / "server.db")
    start = utcnow()
    with db.transaction() as session:
        session.add(Project(id="prj_a", name="A", source_type="sample"))
        session.add(
            ScanRow(
                id="scn_aaaaaa1",
                project_id="prj_a",
                status="completed",
                started_at=start,
                finished_at=start + timedelta(seconds=5),
            )
        )
        session.add(ScanRow(id="scn_bbbbbb2", project_id="prj_a", status="running",
                            started_at=start + timedelta(seconds=10)))  # fmt: skip
        session.flush()
        session.add_all([
            _finding("scn_aaaaaa1", "fp1", "confirmed", "asha"),
            _finding("scn_aaaaaa1", "fp2", "false_positive"),
            _finding("scn_aaaaaa1", "fp3", "fixed"),
            _finding("scn_aaaaaa1", "fp4", "accepted_risk"),
            _finding("scn_bbbbbb2", "fp1"),
            _finding("scn_bbbbbb2", "fp2"),
            _finding("scn_bbbbbb2", "fp3"),
            _finding("scn_bbbbbb2", "fp5"),
        ])  # fmt: skip
        session.flush()
        scan = session.get(ScanRow, "scn_bbbbbb2")
        assert scan is not None
        assert carry_triage(session, scan) == 2
    with db.transaction() as session:
        rows = {r.fingerprint: r for r in session.scalars(
            select(FindingRow).where(FindingRow.scan_id == "scn_bbbbbb2"))}  # fmt: skip
        assert rows["fp1"].status == "confirmed"
        assert rows["fp1"].assignee == "asha"
        assert rows["fp2"].status == "false_positive"
        assert rows["fp3"].status == "open"
        assert rows["fp5"].status == "open"
        events = list(session.scalars(select(FindingEvent)))
        assert {e.finding_id for e in events} == {"scn_bbbbbb2-fp1", "scn_bbbbbb2-fp2"}
        assert all("SCN-AAAAAA" in (e.comment or "") for e in events)
    db.dispose()


def test_carry_triage_without_a_previous_scan(tmp_path: Path) -> None:
    db = Database(tmp_path / "server.db")
    with db.transaction() as session:
        session.add(Project(id="prj_a", name="A", source_type="sample"))
        session.add(ScanRow(id="scn_cccccc3", project_id="prj_a", status="running",
                            started_at=utcnow()))  # fmt: skip
        session.flush()
        scan = session.get(ScanRow, "scn_cccccc3")
        assert scan is not None
        assert carry_triage(session, scan) == 0
    db.dispose()
