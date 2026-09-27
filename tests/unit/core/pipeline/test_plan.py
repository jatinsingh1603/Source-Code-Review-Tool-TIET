from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.core.pipeline.errors import StageCycleError
from codekavach.core.pipeline.plan import (
    ExcludedStage,
    PlanError,
    PlanProblem,
    build_plan,
    check_privacy_structure,
    plan_from_stages,
)
from codekavach.core.pipeline.stage import StageCategory, describe_stage
from codekavach.core.plugins.discovery import PluginSpec
from codekavach.core.plugins.registry import PluginRegistry
from tests.support.pipeline import FakeStage, default_fake_stages

STAGES = "codekavach.stages"
FULL = (
    "ingest", "parse", "analyse-rules", "analyse-taint", "aggregate", "privacy-prepare",
    "llm-review", "restore", "rate", "report", "sync",
)  # fmt: skip
MODULE = """
from tests.support.pipeline import default_fake_stages

for _stage in default_fake_stages():
    globals()[_stage.name.replace("-", "_")] = (lambda stage=_stage: stage)
"""


@pytest.fixture
def registry(fake_site: Path) -> PluginRegistry:
    (fake_site / "ck_plan_stages.py").write_text(MODULE, encoding="utf-8")
    specs = [
        PluginSpec(STAGES, name, f"ck_plan_stages:{name.replace('-', '_')}", "ck-fake", "1")
        for name in FULL
    ]
    return PluginRegistry(specs)


def settings(**llm: bool) -> Settings:
    return Settings.model_validate({"llm": llm} if llm else {})


def test_full_plan(registry: PluginRegistry) -> None:
    plan = build_plan(registry, Settings())
    assert plan.order == FULL
    assert [stage.name for stage in plan.stages] == list(FULL)
    assert plan.excluded == ()
    assert plan.initial_keys == {"scan.target"}
    assert plan.waves[2] == ("analyse-rules", "analyse-taint")


def test_llm_disabled(registry: PluginRegistry) -> None:
    plan = build_plan(registry, settings(enabled=False))
    assert plan.order == (
        "ingest", "parse", "analyse-rules", "analyse-taint", "aggregate", "rate", "report", "sync",
    )  # fmt: skip
    assert plan.excluded == (
        ExcludedStage("llm-review", "llm_disabled"),
        ExcludedStage("privacy-prepare", "llm_disabled"),
        ExcludedStage("restore", "llm_disabled"),
    )


def test_skipping_privacy_with_llm(registry: PluginRegistry) -> None:
    with pytest.raises(PlanError) as error:
        build_plan(registry, Settings(), skip=["privacy-prepare"])
    assert error.value.code == "privacy_skipped_with_llm"
    assert "privacy stage skipped while an LLM stage is active" in str(error.value)


def test_until(registry: PluginRegistry) -> None:
    plan = build_plan(registry, Settings(), until="privacy-prepare")
    assert plan.order[-1] == "privacy-prepare"
    assert {item.name for item in plan.excluded} == {
        "llm-review", "restore", "rate", "report", "sync",
    }  # fmt: skip
    assert {item.reason_code for item in plan.excluded} == {"after_until"}
    assert build_plan(registry, Settings(), until="analyse").order[-1] == "analyse-taint"
    with pytest.raises(PlanError) as error:
        build_plan(registry, Settings(), until="nothing")
    assert error.value.code == "unknown_stage_selector"


def test_config_skip(registry: PluginRegistry) -> None:
    config = Settings.model_validate({"scan": {"skip_stages": ["sync"]}})
    plan = build_plan(registry, config, skip=["report"])
    assert plan.order[-1] == "rate"
    assert {item.name: item.reason_code for item in plan.excluded} == {
        "report": "skipped_by_config",
        "sync": "skipped_by_config",
    }


def test_group_selector_removes_every_analysis_stage() -> None:
    stages = [
        FakeStage("ingest", requires={"scan.target"}, provides={"files"},
                  category=StageCategory.INGEST),
        FakeStage("analyse-rules", requires={"files"}, provides={"candidates.raw"},
                  category=StageCategory.ANALYSE),
        FakeStage("analyse-taint", requires={"files"}, provides={"candidates.raw"},
                  category=StageCategory.ANALYSE),
        FakeStage("report", optional_requires={"candidates.raw"}, provides={"report.outputs"},
                  category=StageCategory.REPORT),
    ]  # fmt: skip
    plan = plan_from_stages(stages, skip=["analyse"])
    assert plan.order == ("ingest", "report")
    assert [item.name for item in plan.excluded] == ["analyse-rules", "analyse-taint"]


def test_unknown_selector(registry: PluginRegistry) -> None:
    with pytest.raises(PlanError) as error:
        build_plan(registry, Settings(), skip=["nope"])
    assert error.value.code == "unknown_stage_selector"


def test_failed_plugin(registry: PluginRegistry, fake_site: Path) -> None:
    specs = [
        *(PluginSpec(STAGES, name, f"ck_plan_stages:{name.replace('-', '_')}", "ck", "1")
          for name in FULL),
        PluginSpec(STAGES, "broken", "ck_missing:Nope", "ck", "1"),
    ]  # fmt: skip
    broken = PluginRegistry(specs)
    with pytest.raises(PlanError) as error:
        build_plan(broken, Settings())
    assert error.value.code == "stage_plugin_failed"
    assert build_plan(broken, Settings(), skip=["broken"]).order == FULL


def with_extra(stage: FakeStage) -> list[FakeStage]:
    return [*default_fake_stages(), stage]


@pytest.mark.parametrize(
    "extra",
    [
        FakeStage("llm-extra", requires={"payloads.sanitised", "files"}, provides={"x"},
                  category=StageCategory.LLM),
        FakeStage("llm-extra", requires={"payloads.sanitised"}, provides={"x"},
                  optional_requires={"candidates"}, category=StageCategory.LLM),
        FakeStage("llm-extra", requires={"payloads.sanitised", "findings"}, provides={"x"},
                  category=StageCategory.LLM),
        FakeStage("llm-extra", requires={"payloads.sanitised", "scan.target"}, provides={"x"},
                  category=StageCategory.LLM),
    ],
)  # fmt: skip
def test_llm_reads_unsanitised(extra: FakeStage) -> None:
    with pytest.raises(PlanError) as error:
        plan_from_stages(with_extra(extra))
    assert error.value.code == "llm_reads_unsanitised"


def test_other_structure_codes() -> None:
    cases = {
        "llm_without_payloads": FakeStage(
            "llm-extra", requires={"verdicts.raw"}, provides={"x"}, category=StageCategory.LLM
        ),
        "sanitised_key_wrong_provider": FakeStage(
            "sneaky", provides={"payloads.sanitised"}, category=StageCategory.ANALYSE
        ),
        "uncategorised_reads_sanitised": FakeStage(
            "mystery", requires={"payloads.sanitised"}, provides={"x"}
        ),
    }
    for code, extra in cases.items():
        stages = with_extra(extra)
        if code == "sanitised_key_wrong_provider":
            stages = [stage for stage in stages if stage.name != "privacy-prepare"]
            stages.append(
                FakeStage("privacy-prepare", provides={"privacy.done"},
                          category=StageCategory.PRIVACY)
            )  # fmt: skip
        with pytest.raises(PlanError) as error:
            plan_from_stages(stages)
        assert error.value.code == code


def test_check_privacy_structure_returns_every_problem() -> None:
    stages = [
        FakeStage("llm-a", requires={"files"}, provides={"x"}, category=StageCategory.LLM),
        FakeStage("reader", requires={"verdicts.raw"}, provides={"y"}),
        FakeStage("privacy", provides={"payloads.sanitised"}, category=StageCategory.PRIVACY),
        FakeStage("llm-b", requires={"payloads.sanitised"}, provides={"verdicts.raw"},
                  category=StageCategory.LLM),
    ]  # fmt: skip
    problems = check_privacy_structure([describe_stage(stage) for stage in stages])
    assert problems == [
        PlanProblem("llm_reads_unsanitised", "llm-a", "files"),
        PlanProblem("llm_without_payloads", "llm-a", "payloads.sanitised"),
        PlanProblem("uncategorised_reads_sanitised", "reader", "verdicts.raw"),
    ]


def test_plan_from_stages_equals_build_plan(registry: PluginRegistry) -> None:
    built = build_plan(registry, Settings(), skip=["sync"])
    direct = plan_from_stages(default_fake_stages(), skip=["sync"])
    assert (built.order, built.waves, built.excluded) == (
        direct.order,
        direct.waves,
        direct.excluded,
    )
    assert dict(built.infos).keys() == dict(direct.infos).keys()


def test_graph_errors_propagate() -> None:
    stages = [
        FakeStage("a", requires={"y"}, provides={"x"}, category=StageCategory.ANALYSE),
        FakeStage("b", requires={"x"}, provides={"y"}, category=StageCategory.ANALYSE),
    ]
    with pytest.raises(StageCycleError):
        plan_from_stages(stages)


@given(st.sets(st.sampled_from(FULL)))
def test_property_privacy_precedes_llm(skipped: set[str]) -> None:
    try:
        plan = plan_from_stages(default_fake_stages(), skip=sorted(skipped))
    except PlanError:
        return
    except Exception as error:  # noqa: BLE001 - graph errors are acceptable outcomes
        assert error.__class__.__name__ in {"UnsatisfiedRequirementError"}
        return
    categories = [plan.infos[name].category for name in plan.order]
    if StageCategory.LLM in categories:
        first_llm = categories.index(StageCategory.LLM)
        assert StageCategory.PRIVACY in categories[:first_llm]
