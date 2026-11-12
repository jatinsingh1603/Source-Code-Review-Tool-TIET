"""The time estimate of a running scan (``eta_seconds``)."""

from datetime import timedelta

import pytest

pytest.importorskip("fastapi")

from codekavach.server.db.models import ScanRow, utcnow
from codekavach.server.routers.scans import eta_seconds


def _row(provider: str, *, send: bool = True) -> ScanRow:
    return ScanRow(
        id="scn_eta",
        project_id="prj_eta",
        status="running",
        progress=50,
        provider=provider,
        send=send,
        started_at=utcnow() - timedelta(seconds=60),
    )


def test_a_local_provider_scan_has_an_estimate() -> None:
    eta = eta_seconds(_row("mock"))
    assert eta is not None
    assert 50 <= eta <= 70


def test_a_remote_provider_scan_has_no_estimate() -> None:
    assert eta_seconds(_row("agentrouter")) is None


def test_a_dry_run_with_a_remote_provider_has_an_estimate() -> None:
    assert eta_seconds(_row("agentrouter", send=False)) is not None
