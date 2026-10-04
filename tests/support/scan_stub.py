"""Scripted ``run_scan()`` outcomes for CLI scan tests."""

from collections.abc import Sequence
from pathlib import Path

import pytest

from codekavach.core.models import ScanStatus
from codekavach.core.models.finding import Finding
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.result import PipelineResult, StageOutcome, StageRun
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.support.factories import make_egress_totals, make_scan, make_summary
from tests.support.fakes import FakeScanOutcome, StubOrchestrator, fake_backend

RUN_SCAN = "codekavach.core.pipeline.runner.run_scan"


def outcome(
    *,
    status: ScanStatus = ScanStatus.COMPLETED,
    order: tuple[str, ...] = ("ingest",),
    failed: tuple[str, ...] = (),
    blocked: int = 0,
    state_dir: Path = Path(".codekavach"),
    findings: Sequence[Finding] | None = None,
) -> FakeScanOutcome:
    """A ``ScanOutcome``-shaped result with the given status and failed stages.

    ``findings`` are stored as the ``findings`` artefact of the scan below ``state_dir``, where
    the CLI reads them for the severity gate; pass a temporary directory.
    """
    runs = tuple(
        StageRun(
            name,
            StageOutcome.FAILED if name in failed else StageOutcome.SUCCEEDED,
            error_code="stage_exception" if name in failed else None,
        )
        for name in order
    )
    result = PipelineResult(
        scan_id="scan_01ARYZ6S410000000000000000",
        status=status,
        order=order,
        waves=tuple((name,) for name in order),
        stage_runs=runs,
        produced_keys=(),
        excluded=(),
    )
    summary = make_summary(egress=make_egress_totals(requests_blocked=blocked))
    finished = status in {ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS}
    scan = make_scan(status=status, summary=summary if finished else None)
    if findings is not None:
        store = OnDiskArtefactStore(StateLayout(state_dir), scan.id)
        store.put(keys.FINDINGS, list(findings))
    return FakeScanOutcome(result=result, scan=scan, state_dir=state_dir)


def install_stub(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> StubOrchestrator:
    """Register a ``StubOrchestrator`` as ``run_scan`` for the CLI."""
    error = kwargs.pop("error", None)
    events = kwargs.pop("events", ())
    stub = StubOrchestrator(
        events=events,  # type: ignore[arg-type]
        outcome=outcome(**kwargs),  # type: ignore[arg-type]
        error=error,  # type: ignore[arg-type]
    )
    fake_backend(monkeypatch, RUN_SCAN, stub)
    return stub
