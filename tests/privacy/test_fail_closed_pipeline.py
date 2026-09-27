"""Regression guard for I4 at stage level: after a privacy failure nothing reaches the LLM stage."""

from typing import Any

import pytest

from codekavach.core.models import ScanStatus
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.orchestrator import Orchestrator
from codekavach.core.pipeline.plan import plan_from_stages
from codekavach.core.pipeline.result import PipelineResult
from codekavach.core.pipeline.stage import Stage, StageInfo
from tests.support.pipeline import FakeStage, default_fake_stages, make_run_context


class TimeoutStyleOrchestrator(Orchestrator):
    """Injects a timeout-style failure after the privacy stage has written its payloads."""

    def _execute_stage(self, stage: Stage, info: StageInfo, stage_ctx: RunContext) -> None:
        super()._execute_stage(stage, info, stage_ctx)
        if info.name == "privacy-prepare":
            raise TimeoutError


def scenario(
    orchestrator: Orchestrator, **privacy: Any
) -> tuple[PipelineResult, RunContext, dict[str, FakeStage]]:
    stages = {stage.name: stage for stage in default_fake_stages()}
    for key, value in privacy.items():
        setattr(stages["privacy-prepare"], key, value)
    ctx = make_run_context()
    ctx.artefacts.put("scan.target", {"target": "repo"})
    result = orchestrator.run(plan_from_stages(list(stages.values())), ctx)
    return result, ctx, stages


@pytest.mark.parametrize(
    ("orchestrator", "privacy"),
    [
        (Orchestrator(), {"_raises": RuntimeError("x"), "_write_before_raise": True}),
        (TimeoutStyleOrchestrator(), {}),
    ],
)
def test_privacy_failure_locks_egress(orchestrator: Orchestrator, privacy: dict[str, Any]) -> None:
    result, ctx, stages = scenario(orchestrator, **privacy)
    assert stages["llm-review"].calls == 0
    assert not ctx.artefacts.has("payloads.sanitised")
    assert ctx.artefacts.has("findings")
    assert result.egress_locked is True
    assert result.status is ScanStatus.COMPLETED_WITH_ERRORS
