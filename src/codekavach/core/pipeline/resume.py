"""Scan checkpoints and the checks that allow an interrupted scan to be resumed (E04-28).

Owning epic: E04.

While a scan runs, the runner keeps ``<state_dir>/scans/<scan_id>/checkpoint.json`` up to date:
after every stage, not only on cancellation, so a killed process is resumable too. Resuming means
running the same scan again under the same identity and letting the stage cache skip what is
done: INGEST and stages with transient outputs run again, completed cacheable stages are cache
hits, and PRIVACY, LLM and RESTORE stages always run again. Because the salt and the settings are
verified to be the same, their payloads are byte-identical to the first attempt (I5). Until the
LLM response cache (E22) exists, a resumed scan may therefore send the same payloads again.

The checkpoint holds identifiers, fingerprints, digests and stage names only: no salt (only its
one-way fingerprint), no target (only its digest, because a path can contain a user or client
name), no client code and no vault material (I3). Mismatch messages name the field and never
print a fingerprint.
"""

import hashlib
from collections.abc import Sequence
from datetime import datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from codekavach.core.log import get_logger
from codekavach.core.pipeline.errors import PipelineError
from codekavach.core.pipeline.result import StageOutcome, StageRun
from codekavach.core.store.layout import StateLayout, StateLayoutError, atomic_write_bytes

CheckpointStatus = Literal["running", "cancelled", "failed", "completed", "completed_with_errors"]
RESUMABLE: Final = frozenset({"running", "cancelled", "failed"})
REUSABLE_OUTCOMES: Final = frozenset({StageOutcome.SUCCEEDED.value, StageOutcome.CACHED.value})
LATEST: Final = "latest"
_REASONS: Final = {
    "checkpoint": "there is no checkpoint to resume from",
    "status": "the scan already completed",
    "codekavach_version": "codekavach_version differs (CodeKavach changed since the scan started)",
    "settings_fingerprint": (
        "settings_fingerprint differs (configuration changed since the scan started)"
    ),
    "salt_fingerprint": "salt_fingerprint differs (the scan salt is not the one the scan used)",
    "target_digest": "target_digest differs (the scan was started for another target)",
}
_log = get_logger("codekavach.pipeline.resume")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CompletedStage(_Frozen):
    """A stage whose run was recorded, that is, after its outputs were committed or discarded."""

    stage: str
    outcome: str
    stage_key: str | None = None


class Checkpoint(_Frozen):
    """How far a scan got, and what a resume must match."""

    v: Literal[1] = 1
    scan_id: str
    status: CheckpointStatus
    codekavach_version: str
    settings_fingerprint: str
    salt_fingerprint: str
    target_digest: str
    order: list[str]
    completed: list[CompletedStage]
    updated_at: datetime

    def reusable_stages(self) -> frozenset[str]:
        """Stages that ended ``succeeded`` or ``cached``: their bindings may be kept."""
        return frozenset(
            entry.stage for entry in self.completed if entry.outcome in REUSABLE_OUTCOMES
        )


class ResumeMismatchError(PipelineError):
    """The scan cannot be resumed; ``field`` names the check that failed."""

    def __init__(self, scan_id: str, field: str) -> None:
        self.scan_id = scan_id
        self.field = field
        super().__init__(f"cannot resume {scan_id}: {_REASONS[field]}; start a new scan")


def target_digest(target: str) -> str:
    """The ``sha256`` of the target string; the checkpoint needs equality only."""
    return hashlib.sha256(target.encode("utf-8")).hexdigest()


def completed_stages(runs: Sequence[StageRun]) -> list[CompletedStage]:
    """The checkpoint entries of ``runs``; stages that were cancelled or never ran are left out."""
    return [
        CompletedStage(stage=run.stage, outcome=run.outcome.value, stage_key=run.stage_key)
        for run in runs
        if run.outcome is not StageOutcome.CANCELLED
    ]


def write_checkpoint(layout: StateLayout, checkpoint: Checkpoint) -> None:
    """Write the checkpoint of its scan atomically with mode 0o600."""
    text = checkpoint.model_dump_json(indent=2) + "\n"
    atomic_write_bytes(layout.checkpoint_path(checkpoint.scan_id), text.encode("utf-8"))


def load_checkpoint(layout: StateLayout, scan_id: str) -> Checkpoint | None:
    """The checkpoint of ``scan_id``, or ``None`` when it is missing or unreadable."""
    try:
        path = layout.checkpoint_path(scan_id)
        if not path.is_file():
            return None
        checkpoint = Checkpoint.model_validate_json(path.read_bytes())
        if checkpoint.scan_id != scan_id:
            raise StateLayoutError("checkpoint of another scan")
        return checkpoint
    except (OSError, ValidationError, StateLayoutError) as error:
        _log.warning("checkpoint_unreadable", error_type=type(error).__name__)
        return None


def find_resumable(layout: StateLayout) -> str | None:
    """The newest scan id whose checkpoint has status ``running``, ``cancelled`` or ``failed``."""
    scans = layout.scans_dir
    if not scans.is_dir():
        return None
    candidates: list[tuple[datetime, str]] = []
    for entry in scans.iterdir():
        if not entry.is_dir():
            continue
        checkpoint = load_checkpoint(layout, entry.name)
        if checkpoint is not None and checkpoint.status in RESUMABLE:
            candidates.append((checkpoint.updated_at, checkpoint.scan_id))
    return max(candidates)[1] if candidates else None


def verify_resume(
    checkpoint: Checkpoint | None,
    *,
    scan_id: str,
    codekavach_version: str,
    settings_fingerprint: str,
    salt_fingerprint: str,
    target: str,
) -> Checkpoint:
    """Return ``checkpoint`` when the scan may continue under the given identity.

    Checked in this order: the checkpoint exists, its status is not ``completed``, then the
    version, the settings fingerprint, the salt fingerprint and the target digest are equal.

    Raises:
        ResumeMismatchError: the first check that fails, named by ``field``.
    """
    if checkpoint is None:
        raise ResumeMismatchError(scan_id, "checkpoint")
    if checkpoint.status == "completed":
        raise ResumeMismatchError(scan_id, "status")
    expected = {
        "codekavach_version": codekavach_version,
        "settings_fingerprint": settings_fingerprint,
        "salt_fingerprint": salt_fingerprint,
        "target_digest": target_digest(target),
    }
    for field, value in expected.items():
        if getattr(checkpoint, field) != value:
            raise ResumeMismatchError(scan_id, field)
    return checkpoint
