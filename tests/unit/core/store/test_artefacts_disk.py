import json
import os
import stat
import threading
from pathlib import Path

import pytest
from pydantic import BaseModel

from codekavach.core.store import layout as layout_module
from codekavach.core.store.artefacts import OnDiskArtefactStore, list_scan_ids
from codekavach.core.store.base import ArtefactCorruptError, ArtefactMissingError
from codekavach.core.store.layout import StateLayout

SCAN_A = "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8P"  # pragma: allowlist secret
SCAN_B = "scan_01J8ZC3W6T5X0Q9V7R4M2N1K8Q"  # pragma: allowlist secret
MARKER = "PLANTEDCONTENT"


class Record(BaseModel):
    path: str


def blobs(root: Path) -> list[Path]:
    return [path for path in (root / "cache" / "blobs").rglob("*") if path.is_file()]


def store(tmp_path: Path, scan_id: str = SCAN_A) -> OnDiskArtefactStore:
    return OnDiskArtefactStore(StateLayout(tmp_path / ".codekavach"), scan_id)


def test_deduplication_across_keys_and_scans(tmp_path: Path) -> None:
    first = store(tmp_path)
    first.put("files", [Record(path="a.py")])
    first.put("candidates", [Record(path="a.py")])
    store(tmp_path, SCAN_B).put("files", [Record(path="a.py")])
    assert len(blobs(tmp_path / ".codekavach")) == 1


def test_readable_from_another_instance(tmp_path: Path) -> None:
    writer = store(tmp_path)
    writer.put("files", [Record(path="a.py")])
    writer.put_part("candidates.raw", "analyse-rules", [Record(path="b.py")])
    writer.put("ast", object(), persist=False)
    reader = OnDiskArtefactStore.open_existing(StateLayout(tmp_path / ".codekavach"), SCAN_A)
    assert reader.get_list("files", Record) == [Record(path="a.py")]
    assert list(reader.get_parts("candidates.raw", Record)) == ["analyse-rules"]
    assert reader.keys() == ("candidates.raw", "files")
    assert reader.ref("files") == writer.ref("files")


def test_open_existing_and_list_scan_ids(tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / ".codekavach")
    assert list_scan_ids(layout) == []
    with pytest.raises(ArtefactMissingError):
        OnDiskArtefactStore.open_existing(layout, SCAN_A)
    store(tmp_path, SCAN_B).put("files", [])
    store(tmp_path, SCAN_A).put("files", [])
    (layout.scans_dir / "not-a-scan").mkdir()
    assert list_scan_ids(layout) == [SCAN_A, SCAN_B]


def test_corruption_is_detected_without_echo(tmp_path: Path) -> None:
    target = store(tmp_path)
    target.put("files", [Record(path=MARKER)])
    (blob,) = blobs(tmp_path / ".codekavach")
    data = bytearray(blob.read_bytes())
    data[-3] ^= 0x01
    blob.write_bytes(bytes(data))
    with pytest.raises(ArtefactCorruptError) as error:
        target.get_list("files", Record)
    assert "files" in str(error.value)
    assert MARKER not in str(error.value)


def test_missing_blob(tmp_path: Path) -> None:
    target = store(tmp_path)
    target.put("files", [Record(path="a.py")])
    (blob,) = blobs(tmp_path / ".codekavach")
    blob.unlink()
    with pytest.raises(ArtefactMissingError):
        target.get_list("files", Record)


def test_binding_format(tmp_path: Path) -> None:
    target = store(tmp_path)
    ref = target.put("files", [Record(path="a.py")])
    index = tmp_path / ".codekavach" / "scans" / SCAN_A / "index"
    binding = json.loads((index / "files.json").read_text())
    assert binding == {
        "v": 1,
        "key": "files",
        "digest": ref.digest,
        "size": ref.size,
        "shape": "list",
        "type": f"{Record.__module__}.{Record.__qualname__}",
    }
    target.put_part("candidates.raw", "analyse-rules", [])
    parts = json.loads((index / "candidates.raw.json").read_text())
    assert set(parts["parts"]) == {"analyse-rules"}


def test_crash_between_blob_and_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = store(tmp_path)
    real = layout_module.atomic_write_bytes
    calls: list[Path] = []

    def crash_on_binding(path: Path, data: bytes) -> None:
        calls.append(path)
        if path.parent.name == "index":
            raise OSError("simulated crash")
        real(path, data)

    monkeypatch.setattr("codekavach.core.store.artefacts.atomic_write_bytes", crash_on_binding)
    with pytest.raises(OSError, match="simulated crash"):
        target.put("files", [Record(path="a.py")])
    monkeypatch.undo()
    assert not target.has("files")
    target.put("files", [Record(path="a.py")])
    assert target.get_list("files", Record) == [Record(path="a.py")]


def test_transient_values_never_touch_disk(tmp_path: Path) -> None:
    target = store(tmp_path)
    target.put("ast", {"tree": MARKER}, persist=False)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert MARKER not in path.read_text(encoding="utf-8", errors="replace")


def test_concurrent_writers_and_modes(tmp_path: Path) -> None:
    target = store(tmp_path)

    def work(thread: int) -> None:
        for index in range(50):
            target.put_part("candidates.raw", f"analyse-{thread:02d}-{index:02d}", [])
            target.put(f"key{thread:02d}.item{index:02d}", {"t": thread, "i": index})

    threads = [threading.Thread(target=work, args=(thread,)) for thread in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    root = tmp_path / ".codekavach"
    assert len(target.get_parts("candidates.raw", Record)) == 16 * 50
    assert len(target.keys()) == 16 * 50 + 1
    assert target.get_json("key07.item33") == {"t": 7, "i": 33}
    for binding in (root / "scans" / SCAN_A / "index").glob("*.json"):
        json.loads(binding.read_text())
    assert not list(root.rglob("*.tmp"))
    for path in tmp_path.rglob("*"):
        assert path.resolve().is_relative_to(root.resolve()) or path == root
        if os.name != "nt" and path.is_relative_to(root) and path != root:
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == (0o700 if path.is_dir() else 0o600), path
