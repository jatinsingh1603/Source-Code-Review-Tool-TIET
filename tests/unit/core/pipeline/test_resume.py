import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codekavach.core.models.ids import new_scan_id
from codekavach.core.pipeline.result import StageOutcome, StageRun
from codekavach.core.pipeline.resume import (
    Checkpoint,
    CompletedStage,
    ResumeMismatchError,
    completed_stages,
    find_resumable,
    load_checkpoint,
    target_digest,
    verify_resume,
    write_checkpoint,
)
from codekavach.core.store.layout import StateLayout

NOW = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)
TARGET = "/work/clients/acme-bank"
SETTINGS_FP = "ab" * 32
SALT_FP = "0123456789abcdef"
VERSION = "0.1.0"


@pytest.fixture
def layout(tmp_path: Path) -> StateLayout:
    return StateLayout(tmp_path / ".codekavach").ensure()


def checkpoint(scan_id: str | None = None, **changes: object) -> Checkpoint:
    values: dict[str, object] = {
        "scan_id": scan_id or new_scan_id(),
        "status": "cancelled",
        "codekavach_version": VERSION,
        "settings_fingerprint": SETTINGS_FP,
        "salt_fingerprint": SALT_FP,
        "target_digest": target_digest(TARGET),
        "order": ["ingest", "analyse", "rate"],
        "completed": [
            CompletedStage(stage="ingest", outcome="succeeded"),
            CompletedStage(stage="analyse", outcome="cached", stage_key="c" * 64),
        ],
        "updated_at": NOW,
    }
    return Checkpoint.model_validate({**values, **changes})


def verify(candidate: Checkpoint | None, **changes: str) -> Checkpoint:
    identity = {
        "scan_id": candidate.scan_id if candidate is not None else "latest",
        "codekavach_version": VERSION,
        "settings_fingerprint": SETTINGS_FP,
        "salt_fingerprint": SALT_FP,
        "target": TARGET,
    }
    return verify_resume(candidate, **{**identity, **changes})


def test_round_trip_and_file_mode(layout: StateLayout) -> None:
    written = checkpoint()
    write_checkpoint(layout, written)
    path = layout.checkpoint_path(written.scan_id)
    assert load_checkpoint(layout, written.scan_id) == written
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    text = path.read_text(encoding="utf-8")
    assert TARGET not in text
    assert "acme" not in text
    assert written.reusable_stages() == {"ingest", "analyse"}


def test_missing_corrupt_and_foreign_checkpoints_load_as_none(layout: StateLayout) -> None:
    scan_id = new_scan_id()
    assert load_checkpoint(layout, scan_id) is None
    assert load_checkpoint(layout, "../escape") is None
    write_checkpoint(layout, checkpoint(scan_id))
    path = layout.checkpoint_path(scan_id)
    path.write_text("{not json", encoding="utf-8")
    assert load_checkpoint(layout, scan_id) is None
    other = checkpoint()
    path.write_text(other.model_dump_json(), encoding="utf-8")
    assert load_checkpoint(layout, scan_id) is None


def test_completed_stages_leave_out_cancelled_runs() -> None:
    runs = [
        StageRun("ingest", StageOutcome.SUCCEEDED),
        StageRun("analyse", StageOutcome.CACHED, stage_key="k" * 64),
        StageRun("lint", StageOutcome.FAILED, error_code="stage_exception"),
        StageRun("aggregate", StageOutcome.SKIPPED, skip_reason="upstream_failed"),
        StageRun("rate", StageOutcome.CANCELLED),
    ]
    entries = completed_stages(runs)
    assert [(entry.stage, entry.outcome) for entry in entries] == [
        ("ingest", "succeeded"),
        ("analyse", "cached"),
        ("lint", "failed"),
        ("aggregate", "skipped"),
    ]
    assert entries[1].stage_key == "k" * 64
    listed = checkpoint(completed=entries)
    assert listed.reusable_stages() == {"ingest", "analyse"}


def test_find_resumable_picks_the_newest_resumable_scan(layout: StateLayout) -> None:
    assert find_resumable(layout) is None
    statuses = ["cancelled", "running", "failed", "completed", "completed_with_errors"]
    written = {}
    for offset, status in enumerate(statuses):
        written[status] = checkpoint(status=status, updated_at=NOW + timedelta(minutes=offset))
        write_checkpoint(layout, written[status])
    (layout.scans_dir / "not-a-scan").mkdir()
    (layout.scans_dir / "stray.txt").write_text("x", encoding="utf-8")
    assert find_resumable(layout) == written["failed"].scan_id
    newer = checkpoint(status="running", updated_at=NOW + timedelta(hours=1))
    write_checkpoint(layout, newer)
    assert find_resumable(layout) == newer.scan_id


def test_find_resumable_without_scans(tmp_path: Path) -> None:
    assert find_resumable(StateLayout(tmp_path / "absent")) is None


def test_verification_passes_for_the_same_identity() -> None:
    for status in ("running", "cancelled", "failed", "completed_with_errors"):
        candidate = checkpoint(status=status)
        assert verify(candidate) is candidate


def test_verification_order_and_fields() -> None:
    with pytest.raises(ResumeMismatchError) as missing:
        verify(None)
    assert missing.value.field == "checkpoint"
    everything = {
        "codekavach_version": "9.9.9",
        "settings_fingerprint": "cd" * 32,
        "salt_fingerprint": "f" * 16,
        "target": "/elsewhere",
    }
    with pytest.raises(ResumeMismatchError) as done:
        verify(checkpoint(status="completed"), **everything)
    assert done.value.field == "status"
    expected = ["codekavach_version", "settings_fingerprint", "salt_fingerprint", "target_digest"]
    differing = dict(everything)
    for field, argument in zip(expected, list(everything), strict=True):
        with pytest.raises(ResumeMismatchError) as info:
            verify(checkpoint(), **differing)
        assert info.value.field == field
        del differing[argument]
    assert verify(checkpoint(), **differing).status == "cancelled"


def test_messages_name_the_field_and_print_no_fingerprint() -> None:
    candidate = checkpoint()
    with pytest.raises(ResumeMismatchError) as info:
        verify(candidate, salt_fingerprint="f" * 16)
    message = str(info.value)
    assert message == (
        f"cannot resume {candidate.scan_id}: salt_fingerprint differs "
        "(the scan salt is not the one the scan used); start a new scan"
    )
    assert SALT_FP not in message
    assert "f" * 16 not in message
    with pytest.raises(ResumeMismatchError) as settings:
        verify(candidate, settings_fingerprint="cd" * 32)
    assert "settings_fingerprint differs (configuration changed since the scan started)" in str(
        settings.value
    )
    assert SETTINGS_FP not in str(settings.value)
