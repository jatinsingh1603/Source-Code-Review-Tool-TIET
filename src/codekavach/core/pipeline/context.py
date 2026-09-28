"""The context object every stage receives.

Owning epic: E04.

``RunContext`` carries configuration, the artefact store, the event bus, the cancellation token,
the budget and the scan salt (ARCHITECTURE section 4). It carries no vault contents. The
orchestrator derives one per stage with ``for_stage``.
"""

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from codekavach.config import Settings
from codekavach.core.pipeline.budget import Budget
from codekavach.core.pipeline.cancel import CancellationToken, ScanCancelledError
from codekavach.core.pipeline.events import (
    EventBus,
    ItemFailed,
    StageProgress,
    WarningRaised,
)
from codekavach.core.pipeline.items import ItemFailureLog
from codekavach.core.pipeline.result import RunLog, StageRun
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.base import ArtefactStore


@dataclass(frozen=True, slots=True)
class ConsentDecision:
    """The operator's decision about remote egress for this scan (built by E05-13 and the APIs).

    ``None`` on ``RunContext.consent`` means no consent was given; the egress guard (E12) fails
    closed when consent is absent or not granted.
    """

    granted: bool
    source: Literal["none", "user-file", "flag", "env"]


@dataclass(frozen=True, slots=True)
class RunContext:
    """Everything a stage may use during a scan."""

    scan_id: str
    config: Settings
    artefacts: ArtefactStore
    events: EventBus
    cancellation: CancellationToken
    budget: Budget
    scan_salt: ScanSalt
    project_root: Path
    state_dir: Path | None = None
    run_log: RunLog = field(default_factory=RunLog)
    item_failures: ItemFailureLog = field(default_factory=ItemFailureLog)
    stage: str | None = None
    consent: ConsentDecision | None = None

    def for_stage(
        self,
        stage: str,
        *,
        artefacts: ArtefactStore | None = None,
        cancellation: CancellationToken | None = None,
    ) -> "RunContext":
        """A copy bound to ``stage``, optionally with a scoped store or a child token."""
        return dataclasses.replace(
            self,
            stage=stage,
            artefacts=artefacts if artefacts is not None else self.artefacts,
            cancellation=cancellation if cancellation is not None else self.cancellation,
        )

    def fail_item(self, item_id: str, error_code: str) -> None:
        """Record that one item of this stage failed, and publish ``ItemFailed`` (E04-20).

        Raises:
            RuntimeError: the context is not bound to a stage.
            ValueError: ``item_id`` or ``error_code`` is malformed (the value is not echoed).
        """
        if self.stage is None:
            raise RuntimeError("fail_item needs a stage context")
        failure = self.item_failures.add(self.stage, item_id, error_code)
        self.events.publish(
            ItemFailed(
                scan_id=self.scan_id,
                stage=failure.stage,
                item_id=failure.item_id,
                error_code=failure.error_code,
            )
        )

    def check_cancelled(self) -> None:
        """Raise ``ScanCancelledError`` when cancelled or when the wall-clock budget is used up."""
        self.cancellation.raise_if_cancelled()
        if self.budget.deadline_exceeded():
            self.cancellation.cancel("deadline")
            raise ScanCancelledError("deadline")

    def remaining_seconds(self) -> float | None:
        """Seconds left of the wall-clock budget, or ``None``."""
        return self.budget.remaining_seconds()

    def emit_progress(self, current: int, total: int | None, unit: str) -> None:
        """Publish ``StageProgress`` for the bound stage."""
        if self.stage is None:
            raise RuntimeError("emit_progress is only available inside a stage")
        self.events.publish(
            StageProgress(
                scan_id=self.scan_id, stage=self.stage, current=current, total=total, unit=unit
            )
        )

    def warn(self, code: str) -> None:
        """Publish ``WarningRaised`` with a machine code."""
        self.events.publish(WarningRaised(scan_id=self.scan_id, stage=self.stage, code=code))

    def stage_runs(self) -> tuple[StageRun, ...]:
        """The stage runs recorded so far."""
        return self.run_log.snapshot()
