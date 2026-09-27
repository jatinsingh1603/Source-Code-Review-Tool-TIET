from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest

from codekavach.config import Settings, load_settings
from codekavach.core.models import ScanStatus
from codekavach.core.models.ids import new_project_id
from codekavach.core.models.scan import Project
from codekavach.core.pipeline.budget import (
    LLM_COST_MICRO_USD,
    LLM_INPUT_TOKENS,
    LLM_OUTPUT_TOKENS,
    LLM_REQUESTS,
)
from codekavach.core.pipeline.context import ConsentDecision, RunContext
from codekavach.core.pipeline.plan import PlanError
from codekavach.core.pipeline.result import PipelineResult, StageOutcome, StageRun
from codekavach.core.pipeline.runner import (
    CREDENTIALS_IN_TARGET,
    assemble_scan,
    build_budget,
    check_target,
    config_hash,
    minimal_summary,
    run_scan,
)
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from codekavach.core.store.memory import InMemoryArtefactStore
from tests.support.pipeline import FakeStage

START = datetime(2026, 9, 24, 10, 0, tzinfo=UTC)
SCAN = "scan_00000000000000000000000001"


def credential_url() -> str:
    # Assembled at run time so that no credential-shaped literal is committed.
    return "https://" + "user" + ":" + "pw" + "@" + "example.invalid/repo.git"


def test_check_target() -> None:
    assert check_target("fixtures/kavachbank") == "fixtures/kavachbank"
    assert check_target("https://example.invalid/repo.git") == "https://example.invalid/repo.git"
    with pytest.raises(ValueError, match="must not contain credentials"):
        check_target(credential_url())
    with pytest.raises(ValueError, match=CREDENTIALS_IN_TARGET):
        check_target("ssh://git" + "@example.invalid/repo.git")


def test_build_budget() -> None:
    settings = Settings.model_validate(
        {
            "scan": {"timeout_seconds": 600},
            "llm": {
                "budget": {
                    "max_requests": 10,
                    "max_total_input_tokens": 1000,
                    "max_total_output_tokens": 500,
                    "max_cost_usd": 1.5,
                }
            },
        }
    )
    budget = build_budget(settings)
    assert budget.remaining(LLM_REQUESTS) == 10
    assert budget.remaining(LLM_INPUT_TOKENS) == 1000
    assert budget.remaining(LLM_OUTPUT_TOKENS) == 500
    assert budget.remaining(LLM_COST_MICRO_USD) == 1_500_000
    budget.start()
    remaining = budget.remaining_seconds()
    assert remaining is not None
    assert 599 < remaining <= 600
    assert build_budget(Settings()).remaining(LLM_REQUESTS) is None


def test_config_hash_ignores_volatile_keys() -> None:
    base = config_hash(Settings())
    assert len(base) == 64
    assert config_hash(Settings.model_validate({"scan": {"jobs": 3}})) == base
    assert config_hash(Settings.model_validate({"privacy": {"level": "L4"}})) != base


def test_minimal_summary() -> None:
    store = InMemoryArtefactStore()
    store.put("files", [{"path": "a"}, {"path": "b"}])
    store.put("candidates", [{"id": 1}])
    store.put("findings", {"not": "findings"})
    summary = minimal_summary(store, 2.5)
    assert (summary.files_scanned, summary.candidates_total, summary.findings_total) == (2, 1, 0)
    assert summary.egress.requests_sent == 0
    assert minimal_summary(InMemoryArtefactStore(), -1).duration_seconds == 0


def result(status: ScanStatus, outcome: StageOutcome) -> PipelineResult:
    code = "stage_exception" if outcome is StageOutcome.FAILED else None
    return PipelineResult(
        scan_id=SCAN,
        status=status,
        order=("a",),
        waves=(("a",),),
        stage_runs=(
            StageRun("a", outcome, error_code=code, error_type="ValueError" if code else None),
        ),
        produced_keys=(),
        excluded=(),
        started_at=START,
        finished_at=START + timedelta(seconds=3),
    )


@pytest.mark.parametrize(
    ("status", "outcome", "has_summary"),
    [
        (ScanStatus.COMPLETED, StageOutcome.SUCCEEDED, True),
        (ScanStatus.COMPLETED_WITH_ERRORS, StageOutcome.FAILED, True),
        (ScanStatus.FAILED, StageOutcome.FAILED, False),
        (ScanStatus.CANCELLED, StageOutcome.CANCELLED, False),
    ],
)
def test_assemble_scan(status: ScanStatus, outcome: StageOutcome, has_summary: bool) -> None:
    project = Project.model_validate({"id": new_project_id(), "name": "bank", "created_at": START})
    store = InMemoryArtefactStore()
    store.put("languages", ["python", "not-a-language"])
    scan = assemble_scan(
        result=result(status, outcome),
        store=store,
        settings=Settings(),
        project=project,
        clock=lambda: START,
    )
    assert scan.status is status
    assert (scan.summary is not None) is has_summary
    assert [language.value for language in scan.languages] == ["python"]
    assert scan.stages[0].error_summary is None
    assert scan.provider is None


class ConsentProbe(FakeStage):
    seen_consent: ClassVar[list[object]] = []

    def run(self, ctx: RunContext) -> None:
        super().run(ctx)
        ConsentProbe.seen_consent.append(ctx.consent)


@pytest.mark.parametrize("consent", [None, ConsentDecision(granted=True, source="flag")])
def test_consent_is_passed_unchanged(
    tmp_path: Path, fake_site: Path, consent: ConsentDecision | None
) -> None:
    (fake_site / "ck_probe.py").write_text(
        "from tests.unit.core.pipeline.test_runner import ConsentProbe\n"
        "from codekavach.core.pipeline.stage import StageCategory\n"
        "def probe():\n"
        "    return ConsentProbe('probe', requires={'scan.target'}, provides={'files'},\n"
        "                        category=StageCategory.INGEST)\n",
        encoding="utf-8",
    )
    registry = PluginRegistry(
        [PluginSpec("codekavach.stages", "probe", "ck_probe:probe", "t", "1")]
    )
    loaded = load_settings(target=tmp_path, env={"CODEKAVACH_HOME": str(tmp_path / "home")})
    ConsentProbe.seen_consent.clear()
    run_scan(
        loaded,
        str(tmp_path),
        salt=ScanSalt.generate(),
        registry=registry,
        store=InMemoryArtefactStore(),
        consent=consent,
    )
    assert ConsentProbe.seen_consent == [consent]


def test_plan_errors_propagate_before_anything_runs(tmp_path: Path) -> None:
    loaded = load_settings(target=tmp_path, env={"CODEKAVACH_HOME": str(tmp_path / "home")})
    with pytest.raises(PlanError):
        run_scan(loaded, "x", salt=ScanSalt.generate(), registry=PluginRegistry([]), skip=["nope"])
    assert not (tmp_path / ".codekavach").exists()
