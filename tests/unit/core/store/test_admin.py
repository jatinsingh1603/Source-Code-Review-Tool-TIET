"""Cache statistics, pruning and clearing (E04-23)."""

import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from codekavach.core.pipeline.memo import DiskItemMemo, memo_key
from codekavach.core.store import admin as admin_module
from codekavach.core.store.admin import (
    HYSTERESIS,
    TMP_MAX_AGE_SECONDS,
    CacheAdmin,
    CacheStats,
    PruneReport,
    cache_probe,
)
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout

KIB = 1024
NOW = 2_000_000_000.0  # a fixed "now" far from the real clock
HOUR = TMP_MAX_AGE_SECONDS
_counter = iter(range(10**9))


class Table(BaseModel):
    names: list[str]


def digest_of(seed: object) -> str:
    return hashlib.sha256(str(seed).encode()).hexdigest()


def scan_id(number: int) -> str:
    return f"scan_{number:026d}"


@pytest.fixture
def layout(tmp_path: Path) -> StateLayout:
    return StateLayout(tmp_path / ".codekavach")


@pytest.fixture
def admin(layout: StateLayout) -> CacheAdmin:
    return CacheAdmin(layout)


def write(path: Path, size: int, age: float = 0.0) -> Path:
    """A file of ``size`` bytes whose modification time is ``age`` seconds before NOW."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    os.utime(path, (NOW - age, NOW - age))
    return path


def blob(layout: StateLayout, seed: object, size: int, age: float = 0.0) -> str:
    digest = digest_of(seed)
    write(layout.blob_path(digest), size, age)
    return digest


def item(
    layout: StateLayout, seed: object, size: int, age: float = 0.0, ns: str = "parse.v1"
) -> Path:
    return write(layout.item_path(ns, digest_of(seed)), size, age)


def bind(layout: StateLayout, number: int, key: str, *digests: str) -> None:
    """A scan whose binding for ``key`` refers to ``digests`` (several: a multi-provider key)."""
    path = layout.index_path(scan_id(number), key)
    path.parent.mkdir(parents=True, exist_ok=True)
    if len(digests) == 1:
        binding: dict[str, Any] = {"v": 1, "key": key, "digest": digests[0], "size": 1}
    else:
        parts = {f"part{i}": {"digest": d, "size": 1} for i, d in enumerate(digests)}
        binding = {"v": 1, "key": key, "parts": parts}
    path.write_text(json.dumps(binding), encoding="utf-8")


def record(layout: StateLayout, seed: object, *digests: str, parts: bool = False) -> Path:
    key = digest_of(seed)
    outputs: dict[str, Any] = {}
    for index, digest in enumerate(digests):
        if parts:
            outputs[f"k{index}"] = {"digest": None, "size": None, "parts": [["stage", digest]]}
        else:
            outputs[f"k{index}"] = {"digest": digest, "size": 1, "parts": []}
    body = {"v": 1, "stage": "parse", "stage_key": key, "outputs": outputs, "created_at": "t",
            "codekavach_version": "0", "duration_ms": 1}  # fmt: skip
    path = layout.stage_record_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def tmp_file(directory: Path, name: str, age: float) -> Path:
    return write(directory / f".{name}.123.abc.tmp", 7, age)


def blob_names(layout: StateLayout) -> set[str]:
    return {path.name for path in layout.blobs_dir.rglob("*") if path.is_file()}


# --- statistics ---------------------------------------------------------------------------------


def test_stats_of_a_missing_state_directory_are_zero(admin: CacheAdmin) -> None:
    assert admin.stats() == CacheStats()
    assert admin.prune(0, 1, now=NOW) == PruneReport()
    assert admin.clear() == PruneReport()


def test_stats_count_exactly(layout: StateLayout, admin: CacheAdmin) -> None:
    blob(layout, "a", 100)
    blob(layout, "b", 200)
    item(layout, 1, 30)
    item(layout, 2, 40, ns="other.v2")
    item(layout, 3, 50)
    record(layout, "r1", digest_of("a"))
    record(layout, "r2", digest_of("b"))
    bind(layout, 1, "files", digest_of("a"))
    bind(layout, 2, "files", digest_of("a"))
    tmp_file(layout.blobs_dir, "one", 10)
    tmp_file(layout.scans_dir / scan_id(1), "two", 10)
    assert admin.stats() == CacheStats(
        blob_count=2, blob_bytes=300, stage_records=2, item_entries=3, item_bytes=120,
        scan_count=2, tmp_files=2,
    )  # fmt: skip


def test_stats_read_no_file_content(
    layout: StateLayout, admin: CacheAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob(layout, "a", 10)
    item(layout, 1, 10)

    def refuse(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("stats read a file")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    monkeypatch.setattr(Path, "read_text", refuse)
    assert admin.stats().blob_count == 1


def test_stats_ignore_other_directories_and_foreign_names(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    write(layout.root / "vault" / "key", 999)
    write(layout.root / "codekavach.db", 999)
    (layout.scans_dir / "not-a-scan").mkdir(parents=True)
    (layout.scans_dir / "scan_lowercase0000000000000000").mkdir()
    assert admin.stats() == CacheStats()


# --- step 1: temporary files ----------------------------------------------------------------------


def test_old_temporary_files_go_and_young_ones_stay(layout: StateLayout, admin: CacheAdmin) -> None:
    old = tmp_file(layout.blobs_dir, "old", HOUR + 1)
    young = tmp_file(layout.blobs_dir, "young", HOUR - 1)
    exact = tmp_file(layout.root / "cache" / "items", "exact", HOUR)
    in_scans = tmp_file(layout.scans_dir / scan_id(1), "scan", HOUR + 100)
    report = admin.prune(10**9, 5, now=NOW)
    assert not old.exists()
    assert not in_scans.exists()
    assert young.exists()
    assert exact.exists()  # "older than one hour" is strict
    assert report.removed_tmp == 2
    assert report.freed_bytes == 14


def test_a_temporary_file_from_the_future_is_kept(layout: StateLayout, admin: CacheAdmin) -> None:
    future = write(layout.blobs_dir / ".x.1.2.tmp", 3, age=-HOUR * 10)
    admin.prune(10**9, 5, now=NOW)
    assert future.exists()


def test_a_temporary_file_does_not_count_as_a_blob(layout: StateLayout, admin: CacheAdmin) -> None:
    tmp_file(layout.blobs_dir / "ab", "pending", 5)
    assert admin.stats().blob_count == 0


# --- steps 2 and 3: protected blobs and old scans ------------------------------------------------


def test_only_the_newest_scans_protect_blobs_and_older_scans_go(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    old, mid, new = (
        blob(layout, "old", 10, 300),
        blob(layout, "mid", 10, 200),
        blob(layout, "new", 10, 100),
    )
    bind(layout, 1, "files", old)
    bind(layout, 2, "files", mid)
    bind(layout, 3, "files", new)
    report = admin.prune(0, 2, now=NOW)  # a budget of zero: everything unprotected goes
    assert report.removed_scans == 1
    assert not layout.scan_dir(scan_id(1)).exists()
    assert layout.scan_dir(scan_id(2)).is_dir()
    assert blob_names(layout) == {mid, new}
    assert report.removed_blobs == 1


def test_multi_provider_bindings_protect_every_part(layout: StateLayout, admin: CacheAdmin) -> None:
    first, second = blob(layout, "p1", 10), blob(layout, "p2", 10)
    stray = blob(layout, "stray", 10)
    bind(layout, 1, "candidates.raw", first, second)
    admin.prune(0, 1, now=NOW)
    assert blob_names(layout) == {first, second}
    assert stray not in blob_names(layout)


def test_keep_scans_larger_than_the_number_of_scans_keeps_them_all(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    kept = blob(layout, "a", 10)
    bind(layout, 1, "files", kept)
    report = admin.prune(0, 1000, now=NOW)
    assert report.removed_scans == 0
    assert blob_names(layout) == {kept}


def test_an_unreadable_binding_protects_nothing_and_does_not_stop_the_prune(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    ok = blob(layout, "ok", 10)
    bind(layout, 1, "files", ok)
    (layout.index_dir(scan_id(1)) / "broken.json").write_text("{not json", encoding="utf-8")
    (layout.index_dir(scan_id(1)) / "odd.json").write_text("[1, 2]", encoding="utf-8")
    admin.prune(0, 1, now=NOW)
    assert blob_names(layout) == {ok}


def test_scan_directories_are_removed_with_everything_in_them(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    bind(layout, 1, "files", blob(layout, "a", 10))
    (layout.scan_dir(scan_id(1)) / "manifest.json").write_text("{}", encoding="utf-8")
    bind(layout, 2, "files", blob(layout, "b", 10))
    report = admin.prune(10**9, 1, now=NOW)
    assert report.removed_scans == 1
    assert not layout.scan_dir(scan_id(1)).exists()
    assert report.freed_bytes >= 2


# --- step 4: eviction ---------------------------------------------------------------------------


def test_the_worked_example_scaled_to_kilobytes(layout: StateLayout, admin: CacheAdmin) -> None:
    # 130 KiB in the cache, 40 KiB of it protected, a budget of 100 KiB: delete the oldest
    # unprotected content until at most 90 KiB are left.
    keep_a, keep_b = blob(layout, "keep-a", 20 * KIB, 5000), blob(layout, "keep-b", 20 * KIB, 4000)
    bind(layout, 1, "files", keep_a, keep_b)
    unprotected = [blob(layout, f"u{index}", 10 * KIB, 1000 - index * 100) for index in range(9)]
    assert admin.stats().blob_bytes == 130 * KIB
    report = admin.prune(100 * KIB, 1, now=NOW)
    assert report.remaining_bytes == 90 * KIB
    assert report.removed_blobs == 4
    assert report.freed_bytes == 40 * KIB
    # u0 is the oldest (age 1000), u8 the newest (age 200): the four oldest went.
    assert blob_names(layout) == {keep_a, keep_b, *unprotected[4:]}


def test_nothing_is_deleted_while_the_cache_is_within_the_budget(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    blob(layout, "a", 40 * KIB, 100)
    item(layout, 1, 40 * KIB, 100)
    report = admin.prune(80 * KIB, 1, now=NOW)  # exactly at the budget
    assert (report.removed_blobs, report.removed_items) == (0, 0)
    assert report.remaining_bytes == 80 * KIB


def test_hysteresis_stops_at_ninety_per_cent(layout: StateLayout, admin: CacheAdmin) -> None:
    for index in range(10):
        blob(layout, f"b{index}", 10 * KIB, 1000 - index)
    report = admin.prune(95 * KIB, 1, now=NOW)  # 100 KiB > 95 KiB: prune to 85.5 KiB
    assert report.remaining_bytes <= HYSTERESIS * 95 * KIB
    assert report.remaining_bytes == 80 * KIB  # whole blobs only
    assert admin.prune(95 * KIB, 1, now=NOW).removed_blobs == 0  # and a second call is quiet


def test_memo_entries_and_blobs_are_evicted_in_one_oldest_first_order(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    oldest = item(layout, "i-old", 10 * KIB, 900)
    middle = blob(layout, "b-mid", 10 * KIB, 500)
    newest = item(layout, "i-new", 10 * KIB, 100)
    report = admin.prune(15 * KIB, 1, now=NOW)  # 30 KiB > 15: down to 13.5 -> delete two
    assert not oldest.exists()
    assert middle not in blob_names(layout)
    assert newest.exists()
    assert (report.removed_items, report.removed_blobs) == (1, 1)


def test_protected_content_alone_over_the_budget_deletes_everything_else(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    protected = blob(layout, "p", 50 * KIB, 10)
    bind(layout, 1, "files", protected)
    blob(layout, "other", 10 * KIB, 20)
    item(layout, 1, 10 * KIB, 30)
    report = admin.prune(10 * KIB, 1, now=NOW)
    assert blob_names(layout) == {protected}
    assert admin.stats().item_entries == 0
    assert report.remaining_bytes == 50 * KIB  # over the budget, but nothing more may go


def test_equal_ages_are_ordered_by_path_so_the_result_is_repeatable(tmp_path: Path) -> None:
    survivors = []
    for run in range(2):
        layout = StateLayout(tmp_path / f"run{run}")
        for index in range(6):
            blob(layout, f"same-{index}", 10 * KIB, 100)
        CacheAdmin(layout).prune(40 * KIB, 1, now=NOW)
        survivors.append(sorted(blob_names(layout)))
    assert survivors[0] == survivors[1]


def test_a_file_that_vanishes_during_eviction_is_not_an_error(
    layout: StateLayout, admin: CacheAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    for index in range(5):
        blob(layout, f"v{index}", 10 * KIB, 500 - index)
    real = admin_module._unlink

    def racing(file: Any) -> bool:
        real(file)  # another process deleted it just before us
        return False

    monkeypatch.setattr(admin_module, "_unlink", racing)
    report = admin.prune(20 * KIB, 1, now=NOW)
    assert report.removed_blobs == 0  # not counted as ours
    assert report.remaining_bytes <= 18 * KIB  # but the space is gone, so the loop went on


def test_a_file_that_cannot_be_removed_is_skipped(
    layout: StateLayout, admin: CacheAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    stuck = blob(layout, "stuck", 10 * KIB, 900)
    blob(layout, "free", 10 * KIB, 100)
    real = Path.unlink

    def unlink(self: Path, *args: Any, **kwargs: Any) -> None:
        if self.name == stuck:
            raise PermissionError("in use")
        real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)
    report = admin.prune(5 * KIB, 1, now=NOW)
    assert stuck in blob_names(layout)
    assert report.removed_blobs == 1


# --- step 5: dangling stage records ---------------------------------------------------------------


def test_records_that_point_at_a_missing_blob_are_removed(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    present = blob(layout, "here", 10)
    good = record(layout, "good", present)
    dangling = record(layout, "dangling", present, digest_of("missing"))
    by_part = record(layout, "by-part", digest_of("missing-part"), parts=True)
    by_part_ok = record(layout, "by-part-ok", present, parts=True)
    report = admin.prune(10**9, 1, now=NOW)
    assert good.exists()
    assert by_part_ok.exists()
    assert not dangling.exists()
    assert not by_part.exists()
    assert report.removed_records == 2


def test_unreadable_records_are_removed_too(layout: StateLayout, admin: CacheAdmin) -> None:
    paths = []
    for index, text in enumerate(["{", "[]", '{"outputs": 5}', '{"outputs": {"k": 5}}', ""]):
        path = layout.stage_record_path(digest_of(f"bad{index}"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    admin.prune(10**9, 1, now=NOW)
    assert not any(path.exists() for path in paths)


def test_evicting_a_blob_makes_its_record_dangling_in_the_same_prune(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    gone = blob(layout, "gone", 10 * KIB, 900)
    stays = blob(layout, "stays", 10 * KIB, 10)
    needs_gone = record(layout, "needs-gone", gone)
    needs_stays = record(layout, "needs-stays", stays)
    admin.prune(15 * KIB, 1, now=NOW)  # 20 KiB > 15: the older blob goes
    assert not needs_gone.exists()
    assert needs_stays.exists()


# --- step 6: empty directories ------------------------------------------------------------------


def test_empty_shard_directories_are_removed(layout: StateLayout, admin: CacheAdmin) -> None:
    only = blob(layout, "only", 10, 100)
    item(layout, 1, 10, 100, ns="empty.v1")
    admin.prune(0, 1, now=NOW)
    assert only not in blob_names(layout)
    assert list(layout.blobs_dir.iterdir()) == []
    assert list((layout.root / "cache" / "items").iterdir()) == []
    assert layout.blobs_dir.is_dir()  # the top directories stay


# --- safety -------------------------------------------------------------------------------------


def symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symbolic links here")


def test_a_symlink_to_a_file_outside_is_neither_followed_nor_deleted(
    layout: StateLayout, admin: CacheAdmin, tmp_path: Path
) -> None:
    outside = write(tmp_path / "outside" / "precious.txt", 500, 10)
    link = layout.blobs_dir / "ab" / digest_of("link")
    symlink_or_skip(link, outside)
    admin.prune(0, 1, now=NOW)
    assert link.is_symlink()
    assert outside.exists() and outside.stat().st_size == 500
    assert admin.stats().blob_count == 0  # a link is not content


def test_a_symlinked_directory_is_not_entered(
    layout: StateLayout, admin: CacheAdmin, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    victim = write(outside / "ab" / "victim", 500, 10)
    symlink_or_skip(layout.blobs_dir / "linked", outside, directory=True)
    admin.prune(0, 1, now=NOW)
    admin.clear(include_scans=True)
    assert victim.exists()
    assert (layout.blobs_dir / "linked").is_symlink()


def test_a_symlinked_scan_directory_is_left_alone(
    layout: StateLayout, admin: CacheAdmin, tmp_path: Path
) -> None:
    outside = tmp_path / "other-scan"
    keepsake = write(outside / "index" / "x.json", 5)
    symlink_or_skip(layout.scans_dir / scan_id(1), outside, directory=True)
    bind(layout, 2, "files", blob(layout, "a", 10))
    admin.prune(10**9, 1, now=NOW)
    admin.clear(include_scans=True)
    assert keepsake.exists()


# --- clear --------------------------------------------------------------------------------------


def populate(layout: StateLayout) -> None:
    digest = blob(layout, "a", 100)
    item(layout, 1, 50)
    record(layout, "r", digest)
    bind(layout, 1, "files", digest)
    tmp_file(layout.blobs_dir, "t", 5)
    write(layout.root / "codekavach.db", 11)
    write(layout.root / "vault" / "keys" / "k", 22)
    write(layout.root / "ledger" / "l.jsonl", 33)


def test_clear_removes_the_cache_and_keeps_everything_else(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    populate(layout)
    report = admin.clear()
    assert admin.stats() == CacheStats(scan_count=1)  # the scan records are still there
    assert (report.removed_blobs, report.removed_items, report.removed_records) == (1, 1, 1)
    assert report.removed_tmp == 1
    assert report.removed_scans == 0
    assert report.remaining_bytes == 0
    assert (layout.root / "codekavach.db").read_bytes() == b"x" * 11
    assert (layout.root / "vault" / "keys" / "k").exists()
    assert (layout.root / "ledger" / "l.jsonl").exists()
    assert layout.index_path(scan_id(1), "files").exists()


def test_clear_with_scans_removes_the_scan_records_too(
    layout: StateLayout, admin: CacheAdmin
) -> None:
    populate(layout)
    report = admin.clear(include_scans=True)
    assert admin.stats() == CacheStats()
    assert report.removed_scans == 1
    assert (layout.root / "codekavach.db").exists()
    assert (layout.root / "vault" / "keys" / "k").exists()
    assert (layout.root / "ledger" / "l.jsonl").exists()


def test_clear_twice_is_quiet(layout: StateLayout, admin: CacheAdmin) -> None:
    populate(layout)
    admin.clear(include_scans=True)
    assert admin.clear(include_scans=True) == PruneReport()


# --- arguments ----------------------------------------------------------------------------------


def test_prune_validates_its_arguments(admin: CacheAdmin) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        admin.prune(-1, 1)
    with pytest.raises(ValueError, match="keep_scans"):
        admin.prune(0, 0)


def test_prune_uses_the_real_clock_by_default(layout: StateLayout, admin: CacheAdmin) -> None:
    recent = tmp_file(layout.blobs_dir, "now", 0)
    os.utime(recent)  # modified now
    admin.prune(10**9, 1)
    assert recent.exists()


# --- recency: a cache hit refreshes the modification time -----------------------------


def test_binding_a_blob_refreshes_its_modification_time(layout: StateLayout) -> None:
    first = OnDiskArtefactStore(layout, scan_id(1))
    ref = first.put("files", {"a": 1})
    assert ref.digest is not None
    path = layout.blob_path(ref.digest)
    long_ago = time.time() - 100_000
    os.utime(path, (long_ago, long_ago))
    OnDiskArtefactStore(layout, scan_id(2)).bind("files", ref)
    assert path.stat().st_mtime > long_ago + 50_000  # touched to the present


def test_a_bound_blob_outlives_an_untouched_one(layout: StateLayout, admin: CacheAdmin) -> None:
    store = OnDiskArtefactStore(layout, scan_id(1))
    reused = store.put("files", {"a": "x" * 5000})
    unused = store.put("other", {"b": "y" * 5000})
    assert reused.digest and unused.digest
    for ref in (reused, unused):
        assert ref.digest is not None
        os.utime(layout.blob_path(ref.digest), (1000, 1000))  # both very old
    OnDiskArtefactStore(layout, scan_id(2)).bind("files", reused)  # a cache hit uses one
    # scan 1 is no longer among the newest, so nothing is protected; the budget fits one blob
    admin = CacheAdmin(layout)
    report = admin.prune(6000, 1, now=NOW)
    assert report.removed_blobs >= 1
    assert layout.blob_path(reused.digest).exists()
    assert not layout.blob_path(unused.digest).exists()


def test_a_memo_hit_refreshes_the_entry_and_changes_the_eviction_order(layout: StateLayout) -> None:
    memo = DiskItemMemo(layout)
    keys = [memo_key("file", str(index)) for index in range(2)]
    for key in keys:
        memo.get_or_compute("parse.v1", key, lambda: Table(names=["x" * 3000]), Table)
    paths = [layout.item_path("parse.v1", key) for key in keys]
    for path in paths:
        os.utime(path, (1000, 1000))  # both very old, so file 0 would be evicted first by name
    DiskItemMemo(layout).get_or_compute("parse.v1", keys[0], lambda: Table(names=[]), Table)
    assert paths[0].stat().st_mtime > 1000 + 1  # the hit touched it
    CacheAdmin(layout).prune(4000, 1, now=NOW)
    assert paths[0].exists()
    assert not paths[1].exists()


# --- the doctor probe ---------------------------------------------------------------------------


def test_cache_probe_has_the_stats_and_the_free_space(layout: StateLayout) -> None:
    blob(layout, "a", 100)
    probe = cache_probe(layout)
    assert probe["blob_count"] == 1
    assert probe["blob_bytes"] == 100
    assert set(probe) == {
        "blob_count", "blob_bytes", "stage_records", "item_entries", "item_bytes",
        "scan_count", "tmp_files", "free_bytes",
    }  # fmt: skip
    assert isinstance(probe["free_bytes"], int)
    assert probe["free_bytes"] > 0


def test_cache_probe_of_a_missing_directory_still_reports_the_disk(layout: StateLayout) -> None:
    assert not layout.root.exists()
    probe = cache_probe(layout)
    assert probe["blob_count"] == 0
    assert isinstance(probe["free_bytes"], int)
    assert not layout.root.exists()  # the probe creates nothing


def test_cache_probe_survives_an_unreadable_disk(
    layout: StateLayout, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_path: object) -> object:
        raise OSError("no disk")

    monkeypatch.setattr(shutil, "disk_usage", refuse)
    assert cache_probe(layout)["free_bytes"] is None


# --- property: the budget holds and the protected blobs are there ------------------------

SIZES = st.integers(min_value=1, max_value=4000)


@given(
    sizes=st.lists(SIZES, min_size=0, max_size=14),
    protected_mask=st.lists(st.booleans(), min_size=14, max_size=14),
    item_sizes=st.lists(SIZES, min_size=0, max_size=6),
    budget=st.integers(min_value=0, max_value=30_000),
)
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_the_budget_holds_whenever_the_unprotected_content_allows_it(
    sizes: list[int],
    protected_mask: list[bool],
    item_sizes: list[int],
    budget: int,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    layout = StateLayout(tmp_path_factory.mktemp("prop") / ".codekavach")
    protected: list[str] = []
    for index, size in enumerate(sizes):
        digest = blob(layout, f"blob-{index}", size, age=index * 10)
        if protected_mask[index]:
            protected.append(digest)
    for index, size in enumerate(item_sizes):
        item(layout, f"item-{index}", size, age=index * 7)
    if protected:
        bind(layout, 1, "files", *protected)
    protected_bytes = sum(layout.blob_path(digest).stat().st_size for digest in protected)
    report = CacheAdmin(layout).prune(budget, 1, now=NOW)
    for digest in protected:
        assert layout.blob_path(digest).is_file()
    assert (
        report.remaining_bytes
        == CacheAdmin(layout).stats().blob_bytes + CacheAdmin(layout).stats().item_bytes
    )
    # Either the unprotected content was enough to reach the target, or only protected is left.
    assert report.remaining_bytes <= max(int(budget * HYSTERESIS), protected_bytes) or (
        report.remaining_bytes <= budget
    )
    if protected_bytes <= budget:
        assert report.remaining_bytes <= budget


POSIX = sys.platform != "win32"
