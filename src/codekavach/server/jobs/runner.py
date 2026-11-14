"""The job runner: a bounded thread pool that runs scans away from the request path.

Owning epic: E32.

At most ``workers`` scans run at a time; the rest wait as ``queued``. Each job has a
``CancellationToken``: cancelling a queued job marks it ``cancelled`` before it starts, and
cancelling a running one makes the pipeline stop at its next checkpoint. Jobs left ``queued`` or
``running`` by a previous process are marked ``failed`` at start-up (``recover``), because their
worker is gone.
"""

import threading
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import TYPE_CHECKING

from sqlalchemy import select

from codekavach.core.log import get_logger
from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.server.db.models import ScanRow, utcnow
from codekavach.server.jobs.scan import ScanJob, execute_scan

if TYPE_CHECKING:
    from codekavach.server.state import ServerState

_log = get_logger("codekavach.server.jobs.runner")

# How long a shutdown waits for cancelled jobs to reach their next checkpoint.
SHUTDOWN_WAIT_SECONDS = 10.0

# Shown on the scan page of a scan the previous server process left unfinished.
RESTARTED_MESSAGE = (
    "The server stopped while this scan was running, so the scan did not finish. "
    "Start it again with Run again with changes; anything already sent is listed in the "
    "egress ledger."
)


class JobRunner:
    """Runs scan jobs on a fixed pool of worker threads."""

    def __init__(self, state: "ServerState", workers: int) -> None:
        self._state = state
        self._pool = ThreadPoolExecutor(
            max_workers=max(1, workers), thread_name_prefix="codekavach-scan"
        )
        self._lock = threading.Lock()
        self._tokens: dict[str, CancellationToken] = {}
        self._futures: dict[str, Future[None]] = {}

    def submit(self, scan_id: str) -> None:
        """Queue the scan ``scan_id``."""
        token = CancellationToken()
        job = ScanJob(scan_id=scan_id, state=self._state, token=token)
        with self._lock:
            self._tokens[scan_id] = token
            self._futures[scan_id] = self._pool.submit(self._run, job)

    def _run(self, job: ScanJob) -> None:
        try:
            execute_scan(job)
        finally:
            with self._lock:
                self._tokens.pop(job.scan_id, None)
                self._futures.pop(job.scan_id, None)

    def cancel(self, scan_id: str) -> bool:
        """Cancel a queued or running scan; False when it is not active in this process."""
        with self._lock:
            token = self._tokens.get(scan_id)
            future = self._futures.get(scan_id)
        if token is None:
            return False
        token.cancel("cancelled")
        if future is not None and future.cancel():
            with self._state.db.transaction() as session:
                row = session.get(ScanRow, scan_id)
                if row is not None:
                    row.status, row.finished_at = "cancelled", utcnow()
            self._state.hub.log(scan_id).append("done", {"status": "cancelled", "error": None})
        return True

    def active(self) -> list[str]:
        """Ids of the scans queued or running in this process."""
        with self._lock:
            return list(self._tokens)

    def wait(self, scan_id: str, timeout: float | None = None) -> None:
        """Block until ``scan_id`` finished (tests and the CLI)."""
        with self._lock:
            future = self._futures.get(scan_id)
        if future is not None:
            try:
                future.result(timeout=timeout)
            except Exception as error:  # noqa: BLE001 - the job recorded its own failure
                _log.warning("server_job_wait_failed", error_type=type(error).__name__)

    def recover(self) -> int:
        """Mark scans orphaned by a previous process as failed; returns how many."""
        with self._state.db.transaction() as session:
            rows = session.scalars(
                select(ScanRow).where(ScanRow.status.in_(("queued", "running")))
            ).all()
            for row in rows:
                row.status = "failed"
                row.error = RESTARTED_MESSAGE
                row.finished_at = utcnow()
            ids = [row.id for row in rows]
        for scan_id in ids:
            self._state.hub.log(scan_id).append(
                "done", {"status": "failed", "error": "server_restarted"}
            )
        return len(ids)

    def shutdown(self, timeout: float = SHUTDOWN_WAIT_SECONDS) -> None:
        """Cancel every job, stop the pool and give running jobs ``timeout`` seconds to stop.

        A cancelled job stops at its next checkpoint. Waiting for it keeps it from opening a
        database connection after the caller has closed the database.
        """
        for scan_id in self.active():
            self.cancel(scan_id)
        with self._lock:
            running = list(self._futures.values())
        self._pool.shutdown(wait=False, cancel_futures=True)
        _, not_done = wait(running, timeout=timeout)
        if not_done:
            _log.warning("server_jobs_still_running", count=len(not_done))
