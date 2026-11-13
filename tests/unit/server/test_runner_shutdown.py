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
from codekavach.server.jobs.scan import ScanJob


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
