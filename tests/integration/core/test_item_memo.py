"""Incremental re-scan through the item memo (E04-22): one edited file recomputes one item.

A fake stage memoises its per-file result. The stage-level cache is bypassed with ``refresh`` so
that the stage runs every time and only the memo decides what is recomputed.
"""

import itertools
import stat
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from codekavach.core.pipeline.cache import StageCache
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.memo import memo_key
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.result import PipelineResult
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.support.pipeline import make_run_context

pytestmark = pytest.mark.usefixtures("log_output")

POSIX = sys.platform != "win32"
NAMESPACE = "parse.symbols.v1"
_scan_ids = itertools.count()


class Symbols(BaseModel):
    file: str
    count: int


def files_of(ctx: RunContext) -> dict[str, str]:
    """The fake file inventory: name to content hash."""
    target = ctx.artefacts.get_json("scan.target")
    assert isinstance(target, dict)
    files = target["files"]
    assert isinstance(files, dict)
    return {str(name): str(sha) for name, sha in files.items()}


class MemoStage:
    """Reads ``scan.target`` (a mapping of file name to content hash) and memoises each file."""

    requires = frozenset({"scan.target"})
    provides = frozenset({"symbols"})
    category = StageCategory.PARSE
    version = "1"

    def __init__(self, name: str = "parse", *, salted: bool = False) -> None:
        self.name = name
        self.salt_dependent = salted
        self.computed: list[str] = []
        self._lock = threading.Lock()

    def _extractor(self, name: str, sha: str) -> Callable[[], Symbols]:
        def extract() -> Symbols:
            with self._lock:
                self.computed.append(name)
            return Symbols(file=name, count=len(sha))

        return extract

    def run(self, ctx: RunContext) -> None:
        files = files_of(ctx)
        total = 0
        for name, sha in sorted(files.items()):
            ctx.check_cancelled()
            key = memo_key(sha, "python", "grammar-1")
            symbols = ctx.memo.get_or_compute(NAMESPACE, key, self._extractor(name, sha), Symbols)
            total += symbols.count
        ctx.artefacts.put("symbols", {"total": total})


def fake_files(count: int = 20, changed: dict[str, str] | None = None) -> dict[str, str]:
    files = {f"src/file_{index:02d}.py": f"hash-{index:02d}" for index in range(count)}
    files.update(changed or {})
    return files


def scan(
    layout: StateLayout,
    stages: list[Any],
    files: dict[str, str],
    *,
    salt: ScanSalt | None = None,
    **orchestrator: Any,
) -> PipelineResult:
    store = OnDiskArtefactStore(layout, f"scan_{next(_scan_ids):026d}")
    ctx = make_run_context(store=store, state_dir=layout.root, salt=salt)
    store.put("scan.target", {"files": files})
    orchestrator.setdefault("refresh", ["parse"])
    return Orchestrator(cache=StageCache(layout), **orchestrator).run(plan_from_stages(stages), ctx)


@pytest.fixture
def layout(tmp_path: Path) -> StateLayout:
    return StateLayout(tmp_path / ".codekavach")


def entry_files(layout: StateLayout) -> list[Path]:
    root = layout.root / "cache" / "items"
    return sorted(root.rglob("*.json")) if root.exists() else []


# --- the 20-file scenario -----------------------------------------------------------------------


def test_twenty_files_then_none_then_exactly_one(layout: StateLayout) -> None:
    stage = MemoStage()
    first = scan(layout, [stage], fake_files())
    assert len(stage.computed) == 20
    assert (first.memo_hits, first.memo_misses) == (0, 20)
    assert len(entry_files(layout)) == 20

    stage.computed.clear()
    second = scan(layout, [stage], fake_files())
    assert stage.computed == []
    assert (second.memo_hits, second.memo_misses) == (20, 0)

    stage.computed.clear()
    third = scan(layout, [stage], fake_files(changed={"src/file_07.py": "hash-07-edited"}))
    assert stage.computed == ["src/file_07.py"]
    assert (third.memo_hits, third.memo_misses) == (19, 1)
    assert len(entry_files(layout)) == 21  # the old entry of the edited file stays until pruned


def test_a_renamed_file_with_the_same_content_hash_is_a_hit_for_the_content_only_key(
    layout: StateLayout,
) -> None:
    # The key above covers the content hash, not the path, so the stage's own extraction (which
    # attaches the path) runs once per distinct hash; a duplicate keeps one entry.
    stage = MemoStage()
    scan(layout, [stage], {"a.py": "same", "b.py": "same", "c.py": "other"})
    assert len(entry_files(layout)) == 2
    assert len(stage.computed) == 2  # b.py reused the entry of a.py within the same scan


def test_the_stage_level_cache_is_independent_of_the_memo(layout: StateLayout) -> None:
    stage = MemoStage()
    scan(layout, [stage], fake_files(), refresh=[])
    stage.computed.clear()
    again = scan(layout, [stage], fake_files(), refresh=[])
    assert stage.computed == []  # the stage itself was served from its cache
    assert (again.memo_hits, again.memo_misses) == (0, 0)  # so it never reached the memo


# --- no cache: a null memo and no files ---------------------------------------------------------


def test_without_the_cache_the_stage_gets_a_null_memo_and_no_file_is_written(
    layout: StateLayout,
) -> None:
    stage = MemoStage()
    first = scan(layout, [stage], fake_files(), use_cache=False)
    second = scan(layout, [stage], fake_files(), use_cache=False)
    assert len(stage.computed) == 40
    assert (first.memo_hits, first.memo_misses, second.memo_hits) == (0, 0, 0)
    assert entry_files(layout) == []
    assert not (layout.root / "cache" / "items").exists()


def test_a_scan_without_a_state_directory_computes_everything(tmp_path: Path) -> None:
    stage = MemoStage()
    ctx = make_run_context()  # no state directory, in-memory artefacts
    ctx.artefacts.put("scan.target", {"files": fake_files(3)})
    result = Orchestrator().run(plan_from_stages([stage]), ctx)  # no stage cache either
    assert len(stage.computed) == 3
    assert (result.memo_hits, result.memo_misses) == (0, 0)
    assert list(tmp_path.iterdir()) == []


# --- salt separation ----------------------------------------------------------------------------


def test_a_salt_dependent_stage_has_its_own_key_space_per_salt(layout: StateLayout) -> None:
    stage = MemoStage(salted=True)
    salt_a, salt_b = ScanSalt.from_hex("0a" * 32), ScanSalt.from_hex("0b" * 32)
    scan(layout, [stage], fake_files(5), salt=salt_a)
    assert len(stage.computed) == 5
    stage.computed.clear()
    same = scan(layout, [stage], fake_files(5), salt=salt_a)
    assert stage.computed == []
    assert same.memo_hits == 5
    other = scan(layout, [stage], fake_files(5), salt=salt_b)
    assert len(stage.computed) == 5
    assert other.memo_hits == 0
    assert len(entry_files(layout)) == 10
    for path in entry_files(layout):
        assert salt_a.fingerprint() not in str(path)
        assert salt_b.fingerprint() not in str(path)


def test_a_stage_that_is_not_salt_dependent_shares_entries_across_salts(
    layout: StateLayout,
) -> None:
    stage = MemoStage(salted=False)
    scan(layout, [stage], fake_files(4), salt=ScanSalt.from_hex("1a" * 32))
    stage.computed.clear()
    result = scan(layout, [stage], fake_files(4), salt=ScanSalt.from_hex("1b" * 32))
    assert stage.computed == []
    assert result.memo_hits == 4


# --- statistics and permissions -------------------------------------------------------------------


def test_statistics_are_summed_over_every_memoising_stage(layout: StateLayout) -> None:
    class SecondStage(MemoStage):
        provides = frozenset({"symbols.more"})
        requires = frozenset({"scan.target"})

        def run(self, ctx: RunContext) -> None:
            files = files_of(ctx)
            for name, sha in sorted(files.items()):
                ctx.memo.get_or_compute(
                    "scan.second.v1",
                    memo_key(sha),
                    self._extractor(name, sha),
                    Symbols,
                )
            ctx.artefacts.put("symbols.more", {"ok": True})

    first, second = MemoStage("parse"), SecondStage("parse-more")
    scan(layout, [first, second], fake_files(6), refresh=["parse"])
    again = scan(layout, [first, second], fake_files(6), refresh=["parse"])
    assert (again.memo_hits, again.memo_misses) == (12, 0)


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_entries_are_private_files_inside_the_state_directory(layout: StateLayout) -> None:
    scan(layout, [MemoStage()], fake_files(3))
    for path in entry_files(layout):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.is_relative_to(layout.root)


def test_the_result_counters_start_at_zero_for_every_run(layout: StateLayout) -> None:
    stage = MemoStage()
    orchestrator = Orchestrator(cache=StageCache(layout), refresh=["parse"])
    for expected in ((0, 20), (20, 0)):
        store = OnDiskArtefactStore(layout, f"scan_{next(_scan_ids):026d}")
        ctx = make_run_context(store=store, state_dir=layout.root)
        store.put("scan.target", {"files": fake_files()})
        result = orchestrator.run(plan_from_stages([stage]), ctx)
        assert (result.memo_hits, result.memo_misses) == expected  # not cumulative
