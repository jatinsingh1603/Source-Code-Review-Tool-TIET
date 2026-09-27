"""Outcomes of stage runs, recorded by the orchestrator.

Owning epic: E04.

``StageRun`` carries codes and exception class names only, never exception text, in line with the
E02 rule that stage results must not store it.
"""

import threading
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from codekavach.core.models import StageStatus
from codekavach.core.models.scan import StageResult

FALLBACK_ERROR_CODES = {"failed": "stage_failed", "timed_out": "timeout"}


class StageOutcome(StrEnum):
    """How one stage run ended."""

    SUCCEEDED = "succeeded"
    CACHED = "cached"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


_STATUS = {
    StageOutcome.SUCCEEDED: StageStatus.SUCCEEDED,
    StageOutcome.CACHED: StageStatus.SUCCEEDED,
    StageOutcome.FAILED: StageStatus.FAILED,
    StageOutcome.TIMED_OUT: StageStatus.FAILED,
    StageOutcome.SKIPPED: StageStatus.SKIPPED,
    StageOutcome.CANCELLED: StageStatus.SKIPPED,
}


@dataclass(frozen=True, slots=True)
class StageRun:
    """One run of one stage."""

    stage: str
    outcome: StageOutcome
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int = 0
    error_code: str | None = None
    error_type: str | None = None
    skip_reason: str | None = None
    blocked_by: str | None = None
    items_in: int | None = None
    items_out: int | None = None
    stage_key: str | None = None

    def to_stage_result(self) -> StageResult:
        """The E02 ``StageResult``; ``error_summary`` is always ``None``."""
        status = _STATUS[self.outcome]
        error_code = None
        if status is StageStatus.FAILED:
            error_code = self.error_code or FALLBACK_ERROR_CODES[self.outcome.value]
        return StageResult(
            name=self.stage,
            status=status,
            started_at=self.started_at,
            finished_at=self.finished_at,
            error_code=error_code,
            error_summary=None,
            items_in=self.items_in,
            items_out=self.items_out,
        )


class RunLog:
    """A thread-safe, append-only list of stage runs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: list[StageRun] = []

    def append(self, run: StageRun) -> None:
        """Record ``run``."""
        with self._lock:
            self._runs.append(run)

    def snapshot(self) -> tuple[StageRun, ...]:
        """The runs recorded so far, in order."""
        with self._lock:
            return tuple(self._runs)
