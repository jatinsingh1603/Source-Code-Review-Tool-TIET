"""SIGINT against a real scan process (E04-29); POSIX only."""

import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import IO

import pytest

from codekavach.core.pipeline.manifest import ScanManifest
from codekavach.core.pipeline.resume import Checkpoint, find_resumable, load_checkpoint
from codekavach.core.pipeline.signals import FIRST_MESSAGE, SECOND_MESSAGE
from codekavach.core.store.layout import StateLayout

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(os.name == "nt", reason="sends POSIX signals to a child process"),
]

HELPER = "tests.integration.core.helpers.run_slow_scan"
REPOSITORY = Path(__file__).resolve().parents[3]
EXIT_SECONDS = 5


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    return root


def environment(mode: str) -> dict[str, str]:
    return {**os.environ, "CK_SLOW_SCAN_MODE": mode, "PYTHONUNBUFFERED": "1"}


def command(repo: Path) -> list[str]:
    return [sys.executable, "-m", HELPER, str(repo)]


@pytest.fixture
def start(repo: Path) -> Iterator["Starter"]:
    starter = Starter(repo)
    yield starter
    for process in starter.processes:
        if process.poll() is None:
            process.kill()
        process.communicate()


class Starter:
    """Starts helper processes and remembers them so that the fixture can reap them."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.processes: list[subprocess.Popen[str]] = []

    def __call__(self, mode: str) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            command(self.repo),
            cwd=REPOSITORY,
            env=environment(mode),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.processes.append(process)
        return process


def read_until(stream: IO[str] | None, marker: str) -> str:
    """Read lines until one contains ``marker``; the pytest timeout bounds the wait."""
    assert stream is not None
    seen = []
    for line in stream:
        seen.append(line)
        if marker in line:
            return "".join(seen)
    raise AssertionError(f"the helper ended without printing {marker!r}: {''.join(seen)}")


def only_checkpoint(repo: Path) -> Checkpoint:
    layout = StateLayout(repo / ".codekavach")
    scans = [entry.name for entry in layout.scans_dir.iterdir() if entry.is_dir()]
    assert len(scans) == 1
    checkpoint = load_checkpoint(layout, scans[0])
    assert checkpoint is not None
    return checkpoint


def test_one_sigint_cancels_gracefully_and_the_scan_resumes(repo: Path, start: Starter) -> None:
    process = start("cooperative")
    read_until(process.stdout, "STAGE_STARTED")
    sent = time.monotonic()
    process.send_signal(signal.SIGINT)
    output, errors = process.communicate(timeout=EXIT_SECONDS)
    assert time.monotonic() - sent < EXIT_SECONDS
    assert process.returncode == 0, errors
    assert "STATUS cancelled" in output
    assert FIRST_MESSAGE in errors
    checkpoint = only_checkpoint(repo)
    assert checkpoint.status == "cancelled"
    assert [entry.stage for entry in checkpoint.completed] == ["ingest"]
    layout = StateLayout(repo / ".codekavach")
    manifest = ScanManifest.model_validate_json(
        layout.manifest_path(checkpoint.scan_id).read_text(encoding="utf-8")
    )
    assert manifest.status == "cancelled"
    assert find_resumable(layout) == checkpoint.scan_id

    resumed = subprocess.run(
        command(repo),
        cwd=REPOSITORY,
        env=environment("resume"),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert resumed.returncode == 0, resumed.stderr
    assert f"SCAN {checkpoint.scan_id}" in resumed.stdout
    assert "STATUS completed" in resumed.stdout
    assert only_checkpoint(repo).status == "completed"


def test_second_sigint_exits_at_once_with_130(repo: Path, start: Starter) -> None:
    process = start("stubborn")
    read_until(process.stdout, "STAGE_STARTED")
    process.send_signal(signal.SIGINT)
    read_until(process.stderr, FIRST_MESSAGE.strip())
    sent = time.monotonic()
    process.send_signal(signal.SIGINT)
    assert process.wait(timeout=EXIT_SECONDS) == 130
    assert time.monotonic() - sent < EXIT_SECONDS
    assert process.stderr is not None
    assert SECOND_MESSAGE in process.stderr.read()
    checkpoint = only_checkpoint(repo)
    assert checkpoint.status == "running"
    assert [entry.stage for entry in checkpoint.completed] == ["ingest"]
