"""Regression guard for I2 at the pipeline level: no plan lets an LLM stage read raw code."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.pipeline.keys import RAW_CODE_KEYS
from codekavach.core.pipeline.plan import PlanError, plan_from_stages
from codekavach.core.pipeline.stage import StageCategory
from tests.support.pipeline import FakeStage, default_fake_stages


@given(
    raw_key=st.sampled_from(sorted(RAW_CODE_KEYS)),
    optional=st.booleans(),
    with_payloads=st.booleans(),
    llm_enabled=st.booleans(),
)
def test_llm_stage_reading_raw_code_is_never_accepted(
    raw_key: str, optional: bool, with_payloads: bool, llm_enabled: bool
) -> None:
    requires = {"payloads.sanitised"} if with_payloads else set()
    extra = FakeStage(
        "llm-intruder",
        requires=requires if optional else requires | {raw_key},
        optional_requires={raw_key} if optional else set(),
        provides={"intruder.out"},
        category=StageCategory.LLM,
    )
    stages = [*default_fake_stages(), extra]
    if not llm_enabled:
        # Disabling the LLM path excludes the intruder; it must never run with raw input.
        plan = plan_from_stages(stages, llm_enabled=False)
        assert "llm-intruder" not in plan.order
        return
    with pytest.raises(PlanError):
        plan_from_stages(stages)
