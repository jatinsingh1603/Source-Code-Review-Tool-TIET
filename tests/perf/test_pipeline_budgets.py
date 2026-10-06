"""Performance budgets of the pipeline, the artefact stores and the cache (E04-32).

The pipeline is on every hot path (a progress event per file, a store access per artefact, a
scoped-store check per call, a lookup per stage, thousands of finding rows per scan), so its
overhead multiplies across later epics and would distort the timings of the evaluation (E36).
Each measurement is the median of five repetitions. The target is what a developer laptop should
achieve; the hard limit is five to ten times higher so that shared CI runners pass, and it is
scaled by ``CODEKAVACH_PERF_FACTOR`` through ``budget()``. A failure of a hard limit is a real
regression, not noise. One line per measurement (``name median_ms target_ms limit_ms``) is written
to the terminal even when output is captured, so a CI log shows the trend. Measured medians are
recorded in the closing comment of E04-32 and in ``docs/reference/pipeline.md`` when that exists.
"""

import itertools
import json
from pathlib import Path

import pytest
from pydantic import BaseModel

from codekavach.config import Settings
from codekavach.core.models.ids import new_finding_id, new_scan_id
from codekavach.core.pipeline.events import Event, InMemoryEventBus, NullEventBus, StageProgress
from codekavach.core.pipeline.graph import build_graph, resolve_order, resolve_waves
from codekavach.core.pipeline.keys import TARGET
from codekavach.core.pipeline.memo import DiskItemMemo, memo_key
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.stage import StageInfo
from codekavach.core.store.admin import CacheAdmin
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.base import encode_artefact
from codekavach.core.store.db import init_db, make_session_factory, session_scope
from codekavach.core.store.layout import StateLayout
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.core.store.repositories import FindingRepository, ProjectRepository, ScanRepository
from codekavach.core.store.scoped import StageScopedStore
from tests.support.factories import make_finding, make_project, make_scan
from tests.support.perf import assert_within_budget, measurement_line, median_seconds
from tests.support.pipeline import FakeStage, layered_stage_infos, make_run_context

pytestmark = pytest.mark.perf

REPEAT = 5


def report(
    capsys: pytest.CaptureFixture[str],
    name: str,
    median: float,
    target_ms: float,
    limit_ms: float,
) -> None:
    """Print the measurement line outside pytest's capture and assert the hard limit."""
    with capsys.disabled():
        print(measurement_line(name, median, target_ms, limit_ms))  # noqa: T201 - the trend
    assert_within_budget(median, limit_ms / 1000, label=name)


# --- the graph -----------------------------------------------------------------------------------


def test_resolve_a_graph_of_500_stages(capsys: pytest.CaptureFixture[str]) -> None:
    infos = layered_stage_infos(10, 50)
    assert len(infos) == 500

    def resolve() -> None:
        graph = build_graph(infos, initial_keys=(TARGET,))
        assert len(resolve_order(graph)) == 500
        assert len(resolve_waves(graph)) == 10

    median = median_seconds(resolve, repeat=REPEAT)

    report(capsys, "resolve_500_stages", median, 50, 500)


# --- the orchestrator ----------------------------------------------------------------------------


def noop_stages(count: int) -> list[FakeStage]:
    return [
        FakeStage(
            f"noop-{index:03d}", provides={f"out.k{index:03d}"}, writes={f"out.k{index:03d}": {}}
        )
        for index in range(count)
    ]


def test_orchestrator_overhead_of_200_noop_stages(capsys: pytest.CaptureFixture[str]) -> None:
    stages = noop_stages(200)
    plan = plan_from_stages(stages)
    settings = Settings.model_validate({"scan": {"jobs": 1}})

    def run() -> None:
        ctx = make_run_context(settings=settings, bus=NullEventBus())
        ctx.artefacts.put(TARGET, {"target": "/work/repo"})
        result = Orchestrator().run(plan, ctx)
        assert len(result.stage_runs) == 200

    median = median_seconds(run, repeat=REPEAT)

    report(capsys, "orchestrator_200_noop_stages", median, 300, 2000)


# --- events --------------------------------------------------------------------------------------


def test_publish_100000_progress_events(capsys: pytest.CaptureFixture[str]) -> None:
    scan_id = new_scan_id()
    events = [
        StageProgress(scan_id=scan_id, stage="parse", current=index, total=100_000, unit="files")
        for index in range(100_000)
    ]

    def publish() -> None:
        bus = InMemoryEventBus()
        seen = itertools.count()

        def count(_event: Event) -> None:
            next(seen)

        bus.subscribe(count)
        for event in events:
            bus.publish(event)

    median = median_seconds(publish, repeat=REPEAT)

    report(capsys, "publish_100000_events", median, 400, 3000)


# --- the on-disk artefact store ------------------------------------------------------------------


def big_payload(seed: int, megabytes: int = 10) -> list[dict[str, object]]:
    """A list of small dicts, like a real artefact, of about ``megabytes`` MiB as JSON."""
    rows: list[dict[str, object]] = []
    size = 0
    index = 0
    while size < megabytes * 1024 * 1024:
        row = {"n": index, "seed": seed, "path": f"src/module_{index % 97}/file_{index}.py",
               "line": index % 500, "rule": "sql-injection", "ok": index % 2 == 0}  # fmt: skip
        rows.append(row)
        size += len(json.dumps(row)) + 2
        index += 1
    return rows


def test_put_and_get_a_10_mib_artefact(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / ".codekavach")
    store = OnDiskArtefactStore(layout, new_scan_id())
    payloads = iter([big_payload(seed) for seed in range(REPEAT)])  # new content each time

    def round_trip() -> None:
        payload = next(payloads)
        store.put("big", payload)
        assert len(store.get_json("big")) == len(payload)  # type: ignore[arg-type]

    median = median_seconds(round_trip, repeat=REPEAT)

    report(capsys, "put_get_10mib_artefact", median, 400, 4000)


# --- the scoped store ----------------------------------------------------------------------------


def test_scoped_store_overhead_is_a_ratio(capsys: pytest.CaptureFixture[str]) -> None:
    inner = InMemoryArtefactStore()
    inner.put("candidates", {"x": 1})
    info = StageInfo(name="probe", requires=frozenset({"candidates"}), provides=frozenset({"out"}))
    scoped = StageScopedStore(inner, info)

    def direct() -> None:
        for _ in range(100_000):
            inner.has("candidates")

    def through_scope() -> None:
        for _ in range(100_000):
            scoped.has("candidates")

    plain = median_seconds(direct, repeat=REPEAT)
    wrapped = median_seconds(through_scope, repeat=REPEAT)
    ratio = wrapped / plain
    with capsys.disabled():
        print(f"scoped_store_has_ratio {ratio:.2f} 2 10")  # noqa: T201 - the trend
    assert_within_budget(ratio, 10.0, label="scoped_store_has_ratio")


# --- the item memo -------------------------------------------------------------------------------


class Symbols(BaseModel):
    file: str
    names: list[str]


def test_5000_memo_hits(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / ".codekavach")
    keys = [memo_key("file", str(index)) for index in range(5000)]
    for index, key in enumerate(keys):  # write the entries directly: the writes are not measured
        path = layout.item_path("parse.symbols.v1", key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encode_artefact(Symbols(file=f"f{index}.py", names=["a", "b"])).data)
    memo = DiskItemMemo(layout)

    def hits() -> None:
        for key in keys:
            memo.get_or_compute("parse.symbols.v1", key, lambda: pytest.fail("a miss"), Symbols)

    median = median_seconds(hits, repeat=REPEAT)
    assert memo.stats().misses == 0
    report(capsys, "memo_5000_hits", median, 1000, 8000)


# --- the database --------------------------------------------------------------------------------


def test_replace_for_scan_with_10000_findings(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    layout = StateLayout(tmp_path / ".codekavach")
    layout.ensure()
    engine = init_db(layout)
    try:
        sessions = make_session_factory(engine)
        scan = make_scan(id=new_scan_id())
        with session_scope(sessions) as session:
            ProjectRepository(session).upsert(make_project())
            ScanRepository(session).add(scan)
        findings = [
            make_finding(id=new_finding_id(), fingerprint=f"ckfp1:{index:032x}")
            for index in range(10_000)
        ]

        def replace() -> None:
            with session_scope(sessions) as session:
                FindingRepository(session).replace_for_scan(scan.id, findings)

        median = median_seconds(replace, repeat=REPEAT)
        with session_scope(sessions) as session:
            assert len(FindingRepository(session).for_scan(scan.id)) == 10_000
    finally:
        engine.dispose()
    report(capsys, "replace_for_scan_10000_findings", median, 2000, 10_000)


# --- the cache -----------------------------------------------------------------------------------


def test_cache_stats_over_20000_files(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / ".codekavach")
    for index in range(20_000):
        digest = f"{index:064x}"
        path = layout.blob_path(digest)
        if index % 256 == 0 or not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * 16)
    admin = CacheAdmin(layout)
    assert admin.stats().blob_count == 20_000
    median = median_seconds(admin.stats, repeat=REPEAT)
    report(capsys, "cache_stats_20000_files", median, 500, 5000)
