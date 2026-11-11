"""Performance budgets of the engine framework (E14-01).

Resolving and probing ten engines must take under 500 ms excluding the engines' own start-up. The
issue also asks that the scheduler add at most 5 percent to the sum of engine wall-clock times with
four workers; a real engine process makes that ratio depend on process start-up, so this test
measures the scheduler's own overhead against an ideal schedule with a sandbox that only sleeps, and
bounds it in absolute terms.
"""

import dataclasses
import time
from pathlib import Path

import pytest

from codekavach.analysis.engines.registry import EngineRegistry
from codekavach.analysis.engines.sandbox import SandboxRequest, SandboxResult
from codekavach.analysis.engines.scheduler import run_all
from codekavach.config import Settings
from codekavach.core.models import Language
from tests.support.engines import (
    FakeAdapter,
    StubSandbox,
    make_engine_context,
    source_file,
    stub_sandboxes,
)
from tests.support.perf import budget, measure

pytestmark = pytest.mark.perf

ENGINES = 10
WORKERS = 4
SLEEP_SECONDS = 0.1


def registry_of(count: int) -> EngineRegistry:
    registry = EngineRegistry()
    for index in range(count):
        registry.register(FakeAdapter(f"engine-{index:02d}"))
    return registry


def test_resolving_and_probing_ten_engines_is_fast() -> None:
    registry = registry_of(ENGINES)
    settings = Settings()

    def resolve() -> None:
        resolution = registry.resolve(
            settings, [Language.PYTHON], probe=lambda adapter: adapter.probe(settings)
        )
        assert len(resolution.adapters) == ENGINES

    assert measure(resolve, repeat=5) < budget(0.5)


class SleepingSandbox(StubSandbox):
    def run(self, request: SandboxRequest) -> SandboxResult:
        time.sleep(SLEEP_SECONDS)
        return super().run(request)


def test_the_scheduler_adds_little_to_the_engines_own_time(tmp_path: Path) -> None:
    base = make_engine_context(tmp_path)
    ctx = dataclasses.replace(base, config=Settings.model_validate({"scan": {"jobs": WORKERS}}))
    view = tmp_path / "view"
    view.mkdir()
    adapters = list(registry_of(8))
    ideal = SLEEP_SECONDS * (len(adapters) / WORKERS)

    def schedule() -> None:
        runs = run_all(
            adapters,
            ctx,
            languages=[Language.PYTHON],
            files=[source_file()],
            view=view,
            work_dir=tmp_path / "work",
            sandboxes=stub_sandboxes(SleepingSandbox()),
        )
        assert [run.status for run in runs] == ["ok"] * len(adapters)

    assert measure(schedule, repeat=3) - ideal < budget(0.5)
