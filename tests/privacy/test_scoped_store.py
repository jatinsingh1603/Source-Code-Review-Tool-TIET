"""Run-time support for I2: an LLM-category stage cannot read raw-code artefacts (E04-17)."""

import pytest

from codekavach.core.pipeline.keys import RAW_CODE_KEYS
from codekavach.core.pipeline.stage import StageCategory, describe_stage
from codekavach.core.store.scoped import StageScopedStore, UndeclaredAccessError
from tests.support.pipeline import FakeStage, make_run_context


@pytest.mark.parametrize("key", sorted(RAW_CODE_KEYS))
def test_llm_stage_cannot_read_raw_code_keys(key: str) -> None:
    ctx = make_run_context()
    info = describe_stage(
        FakeStage(
            "llm-review",
            category=StageCategory.LLM,
            requires={"payloads.sanitised"},
            provides={"verdicts.raw"},
        )
    )
    stage_ctx = ctx.for_stage(info.name, artefacts=StageScopedStore(ctx.artefacts, info))
    for read in (
        lambda: stage_ctx.artefacts.has(key),
        lambda: stage_ctx.artefacts.get_json(key),
        lambda: stage_ctx.artefacts.ref(key),
    ):
        with pytest.raises(UndeclaredAccessError):
            read()
    visible = stage_ctx.artefacts.keys()  # a store, not a dict
    assert key not in visible
