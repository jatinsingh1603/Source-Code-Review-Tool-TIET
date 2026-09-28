import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from codekavach.core.pipeline.cache import (
    StageCache,
    StageCacheRecord,
    compute_stage_key,
    input_digests,
)
from codekavach.core.pipeline.stage import StageCategory, StageInfo
from codekavach.core.store.base import parts_digest
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.memory import InMemoryArtefactStore

INFO = StageInfo(
    name="analyse-rules",
    requires=frozenset({"files"}),
    provides=frozenset({"candidates.raw"}),
    category=StageCategory.ANALYSE,
    version="1",
    origin="ck-fake 1.0",
)
BASE: dict[str, Any] = {
    "config_fp": "c" * 64,
    "salt_fp": "s" * 16,
    "input_digests": {"files": "f" * 64},
}


def key(info: StageInfo = INFO, **changes: Any) -> str:
    return compute_stage_key(info, **{**BASE, **changes})


# key sensitivity and stability


@pytest.mark.parametrize(
    "changed",
    [
        {"info": dataclasses.replace(INFO, name="analyse-taint")},
        {"info": dataclasses.replace(INFO, version="2")},
        {"info": dataclasses.replace(INFO, origin="ck-fake 1.1")},
        {"config_fp": "d" * 64},
        {"salt_fp": "t" * 16},
        {"salt_fp": None},
        {"input_digests": {"files": "e" * 64}},
        {"input_digests": {"files": None}},
        {"input_digests": {"files": "f" * 64, "symbols": None}},
    ],
    ids=["name", "version", "origin", "config", "salt", "no-salt", "input", "absent", "extra"],
)
def test_every_component_changes_the_key(changed: dict[str, Any]) -> None:
    info = changed.pop("info", INFO)
    assert key(info, **changed) != key()


def test_key_is_stable_across_processes() -> None:
    code = (
        "from codekavach.core.pipeline.cache import compute_stage_key\n"
        "from codekavach.core.pipeline.stage import StageCategory, StageInfo\n"
        "info = StageInfo(name='analyse-rules', requires=frozenset({'files'}),\n"
        "    provides=frozenset({'candidates.raw'}), category=StageCategory.ANALYSE,\n"
        "    version='1', origin='ck-fake 1.0')\n"
        "print(compute_stage_key(info, config_fp='c' * 64, salt_fp='s' * 16,\n"
        "    input_digests={'files': 'f' * 64, 'b': None}))\n"
    )
    outputs = set()
    for seed in ("0", "4242"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        result = subprocess.run(
            [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
        )
        outputs.add(result.stdout.strip())
    assert outputs == {key(input_digests={"files": "f" * 64, "b": None})}


# input digests and eligibility


def test_input_digests_rules() -> None:
    store = InMemoryArtefactStore()
    store.put("files", [{"path": "a.py"}])
    ref = store.put_part("candidates.raw", "analyse-rules", [])
    info = StageInfo(
        name="aggregate",
        requires=frozenset({"files", "candidates.raw", "ast"}),
        optional_requires=frozenset({"verdicts.restored"}),
        provides=frozenset({"candidates"}),
    )
    digests = input_digests(
        info, store, transient_producers={"ast": "parse"}, stage_keys={"parse": "p" * 64}
    )
    assert digests == {
        "ast": f"derived:{'p' * 64}:ast",
        "candidates.raw": parts_digest(ref.parts),
        "files": store.ref("files").digest,  # type: ignore[union-attr]
        "verdicts.restored": None,
    }


def test_transient_input_without_producer_key_is_not_cacheable() -> None:
    store = InMemoryArtefactStore()
    info = StageInfo(name="x", requires=frozenset({"ast"}), provides=frozenset({"y"}))
    assert input_digests(info, store, transient_producers={"ast": "parse"}, stage_keys={}) is None
    store.put("ast", object(), persist=False)
    assert input_digests(info, store, transient_producers={}, stage_keys={}) is None


# records


def record(stage_key: str = "a" * 64) -> StageCacheRecord:
    return StageCacheRecord(
        stage="analyse-rules",
        stage_key=stage_key,
        outputs={
            "candidates.raw": {"digest": None, "size": None, "parts": [["analyse-rules", "b" * 64]]}
        },
        created_at="2026-10-01T09:30:00+00:00",
        codekavach_version="0.0.0",
        duration_ms=12,
    )


def test_record_round_trip(tmp_path: Path) -> None:
    cache = StageCache(StateLayout(tmp_path / ".codekavach"))
    cache.store(record())
    assert cache.lookup("a" * 64) == record()
    cache.invalidate("a" * 64)
    assert cache.lookup("a" * 64) is None
    cache.invalidate("a" * 64)  # idempotent


def test_corrupt_and_mismatched_records_are_misses(tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / ".codekavach")
    cache = StageCache(layout)
    cache.store(record())
    path = layout.stage_record_path("a" * 64)
    path.write_bytes(b"{not json")
    assert cache.lookup("a" * 64) is None
    assert not path.exists()
    cache.store(record("c" * 64))
    moved = layout.stage_record_path("d" * 64)
    moved.parent.mkdir(parents=True, exist_ok=True)
    moved.write_bytes(layout.stage_record_path("c" * 64).read_bytes())
    assert cache.lookup("d" * 64) is None
    data = json.loads(layout.stage_record_path("c" * 64).read_text(encoding="utf-8"))
    assert data["v"] == 1
