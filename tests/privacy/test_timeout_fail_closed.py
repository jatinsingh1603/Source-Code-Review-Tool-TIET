"""I4 at stage level: a timed-out privacy stage cannot publish payloads late (E04-18)."""

import time

import pytest

from codekavach.core.pipeline import orchestrator as orchestrator_module
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.result import StageOutcome
from tests.support.pipeline import default_fake_stages, make_run_context


def test_late_payloads_never_become_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        orchestrator_module,
        "resolve_timeout",
        lambda info, *_: 0.1 if info.name == "privacy-prepare" else 5.0,
    )
    stages = default_fake_stages()
    by_name = {stage.name: stage for stage in stages}
    privacy = by_name["privacy-prepare"]
    privacy._sleep_seconds = 0.3
    privacy._cooperative = False
    ctx = make_run_context()
    ctx.artefacts.put("scan.target", {"target": "repo"})
    result = Orchestrator().run(plan_from_stages(stages), ctx)
    time.sleep(0.4)  # the abandoned thread has now tried to write its payloads
    run = result.run_of("privacy-prepare")
    assert run is not None
    assert run.outcome is StageOutcome.TIMED_OUT
    assert result.egress_locked
    assert by_name["llm-review"].calls == 0
    assert not ctx.artefacts.has("payloads.sanitised")
