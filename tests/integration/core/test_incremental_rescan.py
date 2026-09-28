"""Incremental re-scan through the stage cache (E04-21), on the on-disk store."""

import itertools
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.core.pipeline.cache import StageCache
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.result import PipelineResult, StageOutcome
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from tests.support.pipeline import FakeStage, default_fake_stages, make_run_context

pytestmark = pytest.mark.usefixtures("log_output")

CACHEABLE = {"parse", "analyse-rules", "analyse-taint", "aggregate", "rate"}
NEVER = {"ingest", "privacy-prepare", "llm-review", "restore", "report", "sync"}
_scan_ids = itertools.count()


def stages(files: object = "a.py", **versions: str) -> list[FakeStage]:
    """The default fake pipeline in which every output depends on the file inventory."""
    result = default_fake_stages()
    for stage in result:
        parts = set(stage._parts)
        stage._writes = {
            key: {"by": stage.name, "files": files} for key in sorted(stage.provides - parts)
        }
        stage._parts = {key: [{"files": files}] for key in parts}
        if stage.name in versions:
            stage.version = versions[stage.name]
    return result


def scan(
    layout: StateLayout,
    pipeline: list[FakeStage],
    *,
    target: str = "/work/repo",
    **orchestrator: Any,
) -> tuple[PipelineResult, OnDiskArtefactStore]:
    store = OnDiskArtefactStore(layout, f"scan_{next(_scan_ids):026d}")
    ctx = make_run_context(store=store, state_dir=layout.root)
    store.put("scan.target", {"target": target})
    result = Orchestrator(cache=StageCache(layout), **orchestrator).run(
        plan_from_stages(pipeline), ctx
    )
    return result, store


def digests(result: PipelineResult, store: OnDiskArtefactStore) -> dict[str, Any]:
    out = {}
    for key in result.produced_keys:
        ref = store.ref(key)
        out[key] = (ref.digest, ref.parts) if ref else None
    return out


def outcomes(result: PipelineResult) -> dict[str, StageOutcome]:
    return {run.stage: run.outcome for run in result.stage_runs}


@pytest.fixture
def layout(tmp_path: Path) -> StateLayout:
    return StateLayout(tmp_path / ".codekavach")


def test_unchanged_rescan_calls_no_cacheable_stage(layout: StateLayout) -> None:
    pipeline = stages()
    first, store_1 = scan(layout, pipeline)
    second, store_2 = scan(layout, pipeline)
    assert second.cache_hits >= 2
    assert second.cache_hits == len(CACHEABLE)
    by_name = {stage.name: stage for stage in pipeline}
    assert {name for name in CACHEABLE if by_name[name].calls == 1} == CACHEABLE
    assert {name for name in NEVER if by_name[name].calls == 2} == NEVER
    assert all(outcomes(second)[name] is StageOutcome.CACHED for name in CACHEABLE)
    assert digests(first, store_1) == digests(second, store_2)


def test_changed_input_misses_downstream(layout: StateLayout) -> None:
    scan(layout, stages("a.py"))
    changed, _ = scan(layout, stages("b.py"))
    assert changed.cache_hits == 0
    assert all(outcomes(changed)[name] is StageOutcome.SUCCEEDED for name in CACHEABLE)


def test_version_bump_and_refresh_rerun_exactly_that_stage(layout: StateLayout) -> None:
    scan(layout, stages())
    bumped, _ = scan(layout, stages(**{"analyse-rules": "2"}))
    assert outcomes(bumped)["analyse-rules"] is StageOutcome.SUCCEEDED
    assert {n for n in CACHEABLE - {"analyse-rules"} if outcomes(bumped)[n] is StageOutcome.CACHED}
    assert outcomes(bumped)["aggregate"] is StageOutcome.CACHED  # same output digest
    refreshed, _ = scan(layout, stages(**{"analyse-rules": "2"}), refresh=["analyse-rules"])
    assert outcomes(refreshed)["analyse-rules"] is StageOutcome.SUCCEEDED
    assert outcomes(refreshed)["analyse-taint"] is StageOutcome.CACHED
    group, _ = scan(layout, stages(**{"analyse-rules": "2"}), refresh=["analyse"])
    assert outcomes(group)["analyse-rules"] is StageOutcome.SUCCEEDED
    assert outcomes(group)["analyse-taint"] is StageOutcome.SUCCEEDED


def test_use_cache_false_reruns_and_still_writes(tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / "fresh")
    first, _ = scan(layout, stages(), use_cache=False)
    assert first.cache_hits == 0
    again, _ = scan(layout, stages(), use_cache=False)
    assert all(outcomes(again)[name] is StageOutcome.SUCCEEDED for name in CACHEABLE)
    cached, _ = scan(layout, stages())
    assert cached.cache_hits == len(CACHEABLE)


def test_failed_stage_leaves_no_record(layout: StateLayout) -> None:
    pipeline = stages()
    failing = next(stage for stage in pipeline if stage.name == "analyse-rules")
    failing._raises = RuntimeError("boom")
    first, _ = scan(layout, pipeline)
    failed_key = next(run.stage_key for run in first.stage_runs if run.stage == "analyse-rules")
    assert failed_key is None or not layout.stage_record_path(failed_key).exists()
    fixed, _ = scan(layout, stages())
    assert outcomes(fixed)["analyse-rules"] is StageOutcome.SUCCEEDED


def test_timed_out_stage_leaves_no_record(
    layout: StateLayout, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codekavach.core.pipeline import orchestrator as orchestrator_module  # noqa: PLC0415

    monkeypatch.setattr(
        orchestrator_module,
        "resolve_timeout",
        lambda info, *_: 0.05 if info.name == "analyse-taint" else 5.0,
    )
    pipeline = stages()
    slow = next(stage for stage in pipeline if stage.name == "analyse-taint")
    slow._sleep_seconds = 1.0
    result, _ = scan(layout, pipeline)
    assert outcomes(result)["analyse-taint"] is StageOutcome.TIMED_OUT
    monkeypatch.undo()
    rerun, _ = scan(layout, stages())
    assert outcomes(rerun)["analyse-taint"] is StageOutcome.SUCCEEDED


def test_missing_blob_turns_into_a_miss(layout: StateLayout) -> None:
    _, store = scan(layout, stages())
    ref = store.ref("candidates")
    assert ref is not None and ref.digest is not None
    layout.blob_path(ref.digest).unlink()
    second, _ = scan(layout, stages())
    assert outcomes(second)["aggregate"] is StageOutcome.SUCCEEDED


def test_two_directories_share_stage_keys(tmp_path: Path) -> None:
    one, _ = scan(StateLayout(tmp_path / "a"), stages(), target="/work/one/repo")
    two, _ = scan(StateLayout(tmp_path / "b"), stages(), target="/srv/two/repo")
    keys_one = {run.stage: run.stage_key for run in one.stage_runs if run.stage in CACHEABLE}
    keys_two = {run.stage: run.stage_key for run in two.stage_runs if run.stage in CACHEABLE}
    assert keys_one == keys_two
    assert all(keys_one.values())


@given(st.lists(st.sampled_from(["a.py", "b.py", "c.py"]), min_size=1, max_size=4))
@settings(
    max_examples=10,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_cached_scans_equal_uncached(
    tmp_path_factory: pytest.TempPathFactory, sequence: list[str]
) -> None:
    cached_layout = StateLayout(tmp_path_factory.mktemp("cached") / ".codekavach")
    for files in sequence:
        cached, cached_store = scan(cached_layout, stages(files))
        fresh_layout = StateLayout(tmp_path_factory.mktemp("fresh") / ".codekavach")
        plain, plain_store = scan(fresh_layout, stages(files), use_cache=False)
        assert digests(cached, cached_store) == digests(plain, plain_store)
