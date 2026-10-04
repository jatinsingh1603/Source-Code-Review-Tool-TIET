"""SIGINT and SIGTERM against a real ``codekavach scan`` process (E05-14); POSIX only."""

import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import IO

import pytest

from codekavach.core.pipeline.resume import find_resumable, load_checkpoint
from codekavach.core.pipeline.signals import FIRST_MESSAGE
from codekavach.core.store.layout import StateLayout
from tests.support.pipeline import write_fake_distribution

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(os.name == "nt", reason="sends POSIX signals to a child process"),
]

HELPER = "tests.integration.core.helpers.run_slow_scan"
REPOSITORY = Path(__file__).resolve().parents[3]
EXIT_SECONDS = 10


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    return root


@pytest.fixture
def scan(tmp_path: Path, repo: Path) -> Iterator[subprocess.Popen[str]]:
    """A ``codekavach scan`` process whose second stage sleeps cooperatively for 30 seconds."""
    site = tmp_path / "site-packages"
    site.mkdir()
    write_fake_distribution(
        site,
        "ck-slow-stages",
        "1.0",
        entry_points={
            "codekavach.stages": {"ingest": f"{HELPER}:ingest", "analyse-fake": f"{HELPER}:slow"}
        },
        modules={},
    )
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join([str(site), str(REPOSITORY)]),
        "PYTHONUNBUFFERED": "1",
        "CK_SLOW_SCAN_MODE": "cooperative",
        "CODEKAVACH_HOME": str(tmp_path / "home"),
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "codekavach", "scan", str(repo), "--fail-on", "none"],
        cwd=REPOSITORY,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    yield process
    if process.poll() is None:
        process.kill()
    process.communicate()


def read_until(stream: IO[str] | None, marker: str) -> None:
    """Read lines until one contains ``marker``; the pytest timeout bounds the wait."""
    assert stream is not None
    seen = []
    for line in stream:
        seen.append(line)
        if marker in line:
            return
    raise AssertionError(f"the scan ended without printing {marker!r}: {''.join(seen)}")


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM], ids=["sigint", "sigterm"])
def test_signal_cancels_the_scan_with_a_resume_hint(
    scan: subprocess.Popen[str], repo: Path, signum: signal.Signals
) -> None:
    read_until(scan.stdout, "STAGE_STARTED")
    sent = time.monotonic()
    scan.send_signal(signum)
    _, errors = scan.communicate(timeout=EXIT_SECONDS)
    assert time.monotonic() - sent < EXIT_SECONDS
    assert scan.returncode == 130, errors
    assert FIRST_MESSAGE in errors
    layout = StateLayout(repo / ".codekavach")
    scan_id = find_resumable(layout)
    assert scan_id is not None
    assert f"scan {scan_id} cancelled after stage 'ingest'" in errors
    assert f"--resume {scan_id}" in errors
    assert "resume with: codekavach scan" in errors
    checkpoint = load_checkpoint(layout, scan_id)
    assert checkpoint is not None
    assert checkpoint.status == "cancelled"
