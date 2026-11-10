"""Performance budgets of the archive and git sources (E06-03).

A 200 MB archive of 20 000 entries extracts in under 60 seconds; a depth-1 clone of a 50 MB
repository completes in under 30 seconds from a local file-system remote. The network is not
used. The budgets are scaled by the performance factor.
"""

import io
import os
import tarfile
import time
from pathlib import Path

import pytest

from codekavach.config.models.ingest import IngestSettings
from codekavach.ingest.limits import IngestLimits
from codekavach.ingest.sources.archive import safe_extract
from codekavach.ingest.sources.git import GitSource
from tests.support.hostile import all_files, git, has_git
from tests.support.perf import assert_within_budget

EXTRACT_SECONDS = 60.0
CLONE_SECONDS = 30.0
ENTRIES = 20_000
ENTRY_BYTES = 10_240


def limits() -> IngestLimits:
    return IngestLimits.from_settings(IngestSettings())


@pytest.mark.perf
def test_a_two_hundred_megabyte_archive_of_twenty_thousand_entries(tmp_path: Path) -> None:
    archive = tmp_path / "big.tar"
    block = os.urandom(ENTRY_BYTES)
    with tarfile.open(archive, "w") as bundle:
        for index in range(ENTRIES):
            info = tarfile.TarInfo(f"d{index % 200}/f{index}.bin")
            info.size = ENTRY_BYTES
            bundle.addfile(info, io.BytesIO(block))
    started = time.perf_counter()
    root = safe_extract(archive, tmp_path / "out", limits())
    elapsed = time.perf_counter() - started
    assert len(all_files(root)) == ENTRIES
    assert_within_budget(elapsed, EXTRACT_SECONDS, label="200 MB archive extraction")


@pytest.mark.perf
@pytest.mark.skipif(not has_git(), reason="git is not installed")
def test_a_depth_one_clone_of_a_fifty_megabyte_repository(tmp_path: Path) -> None:
    remote = tmp_path / "remote"
    remote.mkdir()
    git(remote, "init", "-q")
    for index in range(50):
        (remote / f"blob{index}.bin").write_bytes(os.urandom(1024 * 1024))
    (remote / "app.py").write_text("x = 1\n", encoding="utf-8")
    git(remote, "add", "-A")
    git(remote, "commit", "-q", "-m", "big")
    started = time.perf_counter()
    root = GitSource().materialise(
        remote.as_uri(), limits=limits(), into=tmp_path / "work" / "tree"
    )
    elapsed = time.perf_counter() - started
    assert (root / "app.py").exists()
    assert_within_budget(elapsed, CLONE_SECONDS, label="depth-1 clone of 50 MB")
