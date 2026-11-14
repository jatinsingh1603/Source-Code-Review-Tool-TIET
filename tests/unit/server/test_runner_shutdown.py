"""``JobRunner.shutdown`` waits for a cancelled job to stop before the caller closes the database.

A job that kept running after ``ServerState.close`` disposed the database opened a new SQLite
connection that nobody closed; Python 3.13 reports it when it is collected, inside whichever test
runs next.
"""

import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("sqlalchemy")

from codekavach.server.jobs import runner as runner_module
from codekavach.server.jobs.runner import JobRunner
from codekavach.server.jobs.scan import SERVER_STOPPED, STOPPED_MESSAGE, ScanJob


def test_shutdown_waits_for_a_running_job_to_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    started = threading.Event()
    finished = threading.Event()

    def slow_job(job: ScanJob) -> None:
        started.set()
        while not job.token.is_cancelled:
            time.sleep(0.01)
        time.sleep(0.2)  # the work up to the next checkpoint
        finished.set()

    monkeypatch.setattr(runner_module, "execute_scan", slow_job)
    state: Any = SimpleNamespace()
    jobs = JobRunner(state, workers=1)
    jobs.submit("scan-1")
    assert started.wait(5)
    jobs.shutdown(timeout=5)
    assert finished.is_set()
    assert jobs.active() == []


def test_shutdown_gives_up_after_its_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()
    started = threading.Event()

    def stuck_job(job: ScanJob) -> None:
        started.set()
        release.wait(5)

    monkeypatch.setattr(runner_module, "execute_scan", stuck_job)
    state: Any = SimpleNamespace()
    jobs = JobRunner(state, workers=1)
    jobs.submit("scan-1")
    assert started.wait(5)
    begin = time.monotonic()
    jobs.shutdown(timeout=0.2)
    assert time.monotonic() - begin < 2
    release.set()


def test_shutdown_tells_running_jobs_the_server_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scan then ends as failed with a message, not as "cancelled by user"."""
    started = threading.Event()
    reasons: list[str | None] = []

    def job_body(job: ScanJob) -> None:
        started.set()
        while not job.token.is_cancelled:
            time.sleep(0.01)
        reasons.append(job.token.reason)

    monkeypatch.setattr(runner_module, "execute_scan", job_body)
    state: Any = SimpleNamespace()
    jobs = JobRunner(state, workers=2)
    jobs.submit("scan-user")
    assert started.wait(5)
    assert jobs.cancel("scan-user")
    jobs.wait("scan-user", timeout=5)
    started.clear()
    jobs.submit("scan-server")
    assert started.wait(5)
    jobs.shutdown(timeout=5)
    assert reasons == ["cancelled", SERVER_STOPPED]


def test_a_scan_stopped_with_the_server_fails_with_a_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codekavach.core.pipeline.cancel import CancellationToken  # noqa: PLC0415
    from codekavach.server.jobs import scan as scan_module  # noqa: PLC0415

    finished: list[tuple[str, str | None]] = []
    lines: list[dict[str, Any]] = []
    log = SimpleNamespace(append=lambda kind, data: lines.append(data))
    token = CancellationToken()
    token.cancel(SERVER_STOPPED)
    job: Any = SimpleNamespace(token=token)
    monkeypatch.setattr(
        scan_module, "_finish", lambda _job, status, *, error=None: finished.append((status, error))
    )
    scan_module._cancelled(job, log)
    assert finished == [("failed", STOPPED_MESSAGE)]
    assert lines[-1]["message"] == STOPPED_MESSAGE
