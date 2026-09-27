import importlib
import importlib.metadata
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from codekavach.core.pipeline.cancel import ScanCancelledError
from codekavach.core.pipeline.events import ScanCancelled
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from tests.support.pipeline import (
    CollectingBus,
    FakeStage,
    make_run_context,
    write_fake_distribution,
)


def test_fake_stage_is_a_valid_stage() -> None:
    info = describe_stage(FakeStage("a", provides={"x"}))
    assert info.provides == frozenset({"x"})
    tagged = FakeStage(
        "b",
        requires={"x"},
        provides={"y"},
        category=StageCategory.ANALYSE,
        failure_policy=FailurePolicy.ABORT_SCAN,
        cacheable=False,
        parallel_safe=False,
        timeout_seconds=5,
    )
    info = describe_stage(tagged)
    assert (info.failure_policy, info.parallel_safe, info.timeout_seconds) == (
        FailurePolicy.ABORT_SCAN, False, 5,
    )  # fmt: skip


def test_default_writes_and_reads() -> None:
    ctx = make_run_context()
    FakeStage("producer", provides={"x", "y"}).run(ctx)
    assert ctx.artefacts.get_json("x") == {"by": "producer"}
    consumer = FakeStage("consumer", requires={"x", "missing"}, provides={"z"})
    consumer.run(ctx)
    assert consumer.seen == {"x": {"by": "producer"}}
    assert consumer.calls == 1


def test_explicit_writes_and_parts() -> None:
    ctx = make_run_context()
    stage = FakeStage(
        "analyse-rules",
        provides={"candidates.raw", "stats"},
        writes={"stats": {"n": 2}},
        parts={"candidates.raw": {"found": 2}},
    )
    stage.run(ctx)
    assert ctx.artefacts.get_json("stats") == {"n": 2}
    assert ctx.artefacts.ref("candidates.raw") is not None
    ref = ctx.artefacts.ref("candidates.raw")
    assert ref is not None
    assert [part for part, _ in ref.parts] == ["analyse-rules"]


def test_default_writes_skip_part_keys() -> None:
    ctx = make_run_context()
    FakeStage("analyse-a", provides={"candidates.raw"}, parts={"candidates.raw": []}).run(ctx)
    assert ctx.artefacts.keys() == ("candidates.raw",)


@pytest.mark.parametrize("before", [True, False])
def test_raise_after_or_before_write(before: bool) -> None:
    ctx = make_run_context()
    stage = FakeStage("boom", provides={"x"}, raises=RuntimeError("x"), write_before_raise=before)
    with pytest.raises(RuntimeError):
        stage.run(ctx)
    assert ctx.artefacts.has("x") is before


def test_cooperative_cancellation() -> None:
    ctx = make_run_context()
    stage = FakeStage("slow", provides={"x"}, sleep_seconds=5)
    threading.Timer(0.05, ctx.cancellation.cancel).start()
    with pytest.raises(ScanCancelledError):
        stage.run(ctx)
    assert not ctx.artefacts.has("x")


def test_uncooperative_stage_finishes_its_sleep() -> None:
    ctx = make_run_context()
    ctx.cancellation.cancel()
    FakeStage("stubborn", provides={"x"}, sleep_seconds=0.03, cooperative=False).run(ctx)
    assert ctx.artefacts.has("x")


def test_make_run_context_is_deterministic() -> None:
    first, second = make_run_context(), make_run_context()
    assert first.scan_id == second.scan_id == "scan_00000000000000000000000000"
    assert first.scan_salt.fingerprint() == second.scan_salt.fingerprint()
    assert first.artefacts is not second.artefacts
    assert isinstance(first.events, CollectingBus)
    assert make_run_context(random_scan_id=True).scan_id != first.scan_id
    assert make_run_context(scan_id="scan_x").scan_id == "scan_x"


def test_collecting_bus() -> None:
    bus = CollectingBus()
    bus.publish(ScanCancelled(scan_id="scan_x", stages_completed=1))
    assert bus.kinds() == ["scan.cancelled"]
    assert bus.of("scan.cancelled")[0].seq == 1
    assert bus.of("scan.started") == []


SAMPLE = (
    "class SampleStage:\n"
    "    name = 'sample'\n"
    "    requires = frozenset()\n"
    "    provides = frozenset({{'sample.out'}})\n"
    "    marker = {marker!r}\n"
    "    def run(self, ctx):\n"
    "        ctx.artefacts.put('sample.out', {{'ok': True}})\n"
)


def install(site: Path, marker: str) -> None:
    write_fake_distribution(
        site,
        "ck-sample-plugin",
        "0.1.0",
        entry_points={
            "codekavach.stages": {"sample": "ck_sample:SampleStage", "broken": "ck_missing:Nope"}
        },
        modules={"ck_sample.py": SAMPLE.format(marker=marker)},
    )


def load_sample() -> Any:
    (entry,) = [
        point
        for point in importlib.metadata.entry_points(group="codekavach.stages")
        if point.name == "sample"
    ]
    return entry.load()


@pytest.mark.parametrize("marker", ["first", "second"])
def test_fake_distribution_is_isolated(fake_site: Path, marker: str) -> None:
    assert "ck_sample" not in sys.modules
    install(fake_site, marker)
    stage_class = load_sample()
    assert stage_class.marker == marker
    assert importlib.metadata.version("ck-sample-plugin") == "0.1.0"
    ctx = make_run_context()
    stage_class().run(ctx)
    assert ctx.artefacts.get_json("sample.out") == {"ok": True}


def test_fake_modules_are_gone_after_the_fixture() -> None:
    assert "ck_sample" not in sys.modules
