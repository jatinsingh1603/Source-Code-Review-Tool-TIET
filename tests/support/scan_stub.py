"""Scripted ``run_scan()`` outcomes for CLI scan tests."""

from pathlib import Path

import pytest

from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.result import PipelineResult, StageOutcome, StageRun
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
) -> FakeScanOutcome:
    """A ``ScanOutcome``-shaped result with the given status and failed stages."""
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
    return FakeScanOutcome(result=result, scan=scan, state_dir=state_dir)


def install_stub(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> StubOrchestrator:
    """Register a ``StubOrchestrator`` as ``run_scan`` for the CLI."""
    error = kwargs.pop("error", None)
    stub = StubOrchestrator(outcome=outcome(**kwargs), error=error)  # type: ignore[arg-type]
    fake_backend(monkeypatch, RUN_SCAN, stub)
    return stub
