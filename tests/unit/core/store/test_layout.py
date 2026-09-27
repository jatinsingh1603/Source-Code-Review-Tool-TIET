import os
import re
import secrets
import stat
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.pipeline.keys import KEY_PATTERN
from codekavach.core.store.layout import (
    StateLayout,
    StateLayoutError,
    atomic_write_bytes,
    secure_mkdir,
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX modes and symlinks")
DIGEST = "ab" + "0" * 62
SCAN = "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P"  # pragma: allowlist secret


def test_accessor_paths(tmp_path: Path) -> None:
    root = tmp_path / ".codekavach"
    layout = StateLayout(root)
    base = root.resolve()
    assert layout.blobs_dir == root / "cache" / "blobs"
    assert layout.blob_path(DIGEST) == base / "cache/blobs/ab" / DIGEST
    assert layout.stage_record_path(DIGEST) == base / "cache/stages/ab" / f"{DIGEST}.json"
    assert layout.items_dir("llm.cache") == base / "cache/items/llm.cache"
    assert layout.item_path("llm.cache", DIGEST) == base / "cache/items/llm.cache/ab" / (
        f"{DIGEST}.json"
    )
    assert layout.scans_dir == root / "scans"
    assert layout.scan_dir(SCAN) == base / "scans" / SCAN
    assert layout.index_dir(SCAN) == base / "scans" / SCAN / "index"
    assert layout.index_path(SCAN, "candidates.raw") == base / "scans" / SCAN / "index" / (
        "candidates.raw.json"
    )
    assert layout.manifest_path(SCAN).name == "manifest.json"
    assert layout.snapshot_path(SCAN).name == "config-snapshot.json"
    assert layout.checkpoint_path(SCAN).name == "checkpoint.json"
    assert layout.db_path == root / "codekavach.db"
    assert not root.exists()  # accessors never touch the file system


@pytest.mark.parametrize(
    "call",
    [
        lambda layout: layout.scan_dir("../x"),
        lambda layout: layout.scan_dir("scan_" + "I" * 26),
        lambda layout: layout.items_dir("a/../../b"),
        lambda layout: layout.items_dir("a..b"),
        lambda layout: layout.blob_path("a" * 63),
        lambda layout: layout.blob_path("A" * 64),
        lambda layout: layout.stage_record_path("../" + "a" * 61),
        lambda layout: layout.item_path("ns", "x"),
        lambda layout: layout.index_path(SCAN, "../x"),
        lambda layout: layout.index_path(SCAN, "A"),
    ],
)
def test_invalid_components(tmp_path: Path, call: object) -> None:
    with pytest.raises(StateLayoutError):
        call(StateLayout(tmp_path))  # type: ignore[operator]


def test_contain(tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / "state")
    assert layout.contain(tmp_path / "state" / "x") == (tmp_path / "state" / "x").resolve()
    with pytest.raises(StateLayoutError):
        layout.contain(tmp_path / "state" / ".." / "other")


def test_key_pattern_matches_keys_module() -> None:
    assert KEY_PATTERN == r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"


def test_atomic_write(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "file.json"
    atomic_write_bytes(target, b"one")
    atomic_write_bytes(target, b"two")
    assert target.read_bytes() == b"two"
    assert not list(target.parent.glob("*.tmp"))
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700


def test_atomic_write_failure_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(descriptor: int) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", broken)
    target = tmp_path / "file.json"
    with pytest.raises(OSError, match="disk full"):
        atomic_write_bytes(target, b"data")
    assert list(tmp_path.iterdir()) == []


@posix_only
def test_atomic_write_refuses_planted_temporary_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    monkeypatch.setattr(secrets, "token_hex", lambda size: "fixed")
    target = tmp_path / "file.json"
    (tmp_path / f".file.json.{os.getpid()}.fixed.tmp").symlink_to(victim)
    with pytest.raises(FileExistsError):
        atomic_write_bytes(target, b"data")
    assert victim.read_bytes() == b"keep"
    assert not target.exists()


@posix_only
def test_secure_mkdir_refuses_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(StateLayoutError):
        secure_mkdir(link)


def test_secure_mkdir_refuses_file(tmp_path: Path) -> None:
    path = tmp_path / "file"
    path.write_text("")
    with pytest.raises(FileExistsError):
        secure_mkdir(path)


def test_ensure(tmp_path: Path) -> None:
    root = tmp_path / "project" / ".codekavach"
    root.parent.mkdir()
    (root.parent / "keep.txt").write_text("x")
    StateLayout(root).ensure()
    assert (root / ".gitignore").read_text() == "*\n"
    assert sorted(path.name for path in root.parent.iterdir()) == [".codekavach", "keep.txt"]
    assert (root.parent / "keep.txt").read_text() == "x"


@posix_only
def test_ensure_refuses_symlinked_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    root = tmp_path / ".codekavach"
    root.symlink_to(real)
    with pytest.raises(StateLayoutError):
        StateLayout(root).ensure()


@given(st.text(max_size=80))
def test_property_contained_or_refused(text: str) -> None:
    root = Path("state-root")
    layout = StateLayout(root)
    calls: list[Callable[[], Path]] = [
        lambda: layout.scan_dir(text),
        lambda: layout.items_dir(text),
        lambda: layout.index_path(SCAN, text),
    ]
    for call in calls:
        try:
            path = call()
        except StateLayoutError:
            continue
        assert path.is_relative_to(root.resolve())
        assert re.search(r"(^|[\\/])\.\.([\\/]|$)", str(path)) is None
