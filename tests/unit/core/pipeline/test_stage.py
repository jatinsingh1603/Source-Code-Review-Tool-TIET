from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.pipeline.errors import PipelineError, StageDeclarationError
from codekavach.core.pipeline.stage import (
    CATEGORY_DEFAULTS,
    FailurePolicy,
    Stage,
    StageCategory,
    StageInfo,
    describe_stage,
)


class CountFiles:
    name = "count-files"
    requires = frozenset({"files"})
    provides = frozenset({"stats.file_count"})

    def run(self, ctx: Any) -> None:
        del ctx


def make(**attributes: Any) -> object:
    """A stage instance with the minimal members overridden or extended by ``attributes``."""
    stage = CountFiles()
    for key, value in attributes.items():
        setattr(stage, key, value)
    return stage


def test_minimal_stage_gets_strict_defaults() -> None:
    info = describe_stage(CountFiles(), origin="demo-plugin 1.0")
    assert info == StageInfo(
        name="count-files",
        requires=frozenset({"files"}),
        provides=frozenset({"stats.file_count"}),
        origin="demo-plugin 1.0",
    )
    assert info.failure_policy is FailurePolicy.FAIL_CLOSED
    assert info.cacheable is False
    assert info.salt_dependent is True
    assert info.version == "0"
    assert isinstance(CountFiles(), Stage)


@pytest.mark.parametrize("category", [*StageCategory, None])
def test_category_defaults(category: StageCategory | None) -> None:
    info = describe_stage(make(category=category))
    policy, cacheable, salt = CATEGORY_DEFAULTS[category]
    assert (info.failure_policy, info.cacheable, info.salt_dependent) == (policy, cacheable, salt)


def test_category_values_are_stage_names() -> None:
    assert [category.value for category in StageCategory] == [
        "ingest", "parse", "analyse", "aggregate", "privacy-prepare",
        "llm-review", "restore", "rate", "report", "sync",
    ]  # fmt: skip


BAD: list[tuple[str, dict[str, Any]]] = [
    ("name", {"name": "Count_Files"}),
    ("name", {"name": "x" * 49}),
    ("requires", {"requires": {"files"}}),
    ("requires", {"requires": frozenset({1})}),
    ("provides", {"provides": frozenset({"Bad-Key"})}),
    ("provides", {"provides": frozenset({"a" * 65})}),
    ("provides", {"provides": frozenset()}),
    ("overlap", {"provides": frozenset({"files"})}),
    ("overlap", {"optional_requires": frozenset({"files"})}),
    ("overlap", {"optional_requires": frozenset({"stats.file_count"})}),
    ("transient_provides", {"transient_provides": frozenset({"other"})}),
    ("run", {"run": "not callable"}),
    (
        "failure_policy",
        {"category": StageCategory.PRIVACY, "failure_policy": FailurePolicy.DEGRADE},
    ),
    ("cacheable", {"category": StageCategory.PRIVACY, "cacheable": True}),
    ("salt_dependent", {"category": StageCategory.LLM, "salt_dependent": False}),
    ("failure_policy", {"failure_policy": FailurePolicy.DEGRADE}),
    ("cacheable", {"category": StageCategory.RESTORE, "cacheable": True}),
    ("cacheable", {"category": StageCategory.SYNC, "cacheable": True}),
    ("cacheable", {"category": StageCategory.INGEST, "cacheable": True}),
    ("plugin API 2", {"plugin_api": 2}),
    ("version", {"version": ""}),
    ("version", {"version": "1 0"}),
    ("category", {"category": "analyse"}),
    ("timeout_seconds", {"timeout_seconds": 0}),
    ("timeout_seconds", {"timeout_seconds": True}),
    ("parallel_safe", {"parallel_safe": "yes"}),
    ("config_sections", {"config_sections": ["scan"]}),
]


@pytest.mark.parametrize(("word", "attributes"), BAD)
def test_invalid_declarations(word: str, attributes: dict[str, Any]) -> None:
    with pytest.raises(StageDeclarationError) as error:
        describe_stage(make(**attributes))
    assert word in str(error.value)
    assert isinstance(error.value, PipelineError)
    if "name" not in attributes:
        assert error.value.stage == "count-files"
        assert "count-files" in str(error.value)


def test_plugin_api_message() -> None:
    with pytest.raises(
        StageDeclarationError, match="targets plugin API 2; this CodeKavach supports 1"
    ):
        describe_stage(make(plugin_api=2))


def test_tightening_is_accepted() -> None:
    info = describe_stage(
        make(category=StageCategory.ANALYSE, failure_policy=FailurePolicy.ABORT_SCAN)
    )
    assert info.failure_policy is FailurePolicy.ABORT_SCAN
    info = describe_stage(
        make(category=StageCategory.PRIVACY, failure_policy=FailurePolicy.ABORT_SCAN)
    )
    assert info.failure_policy is FailurePolicy.ABORT_SCAN


def test_transient_provides_disables_cache() -> None:
    info = describe_stage(
        make(
            category=StageCategory.PARSE,
            cacheable=True,
            transient_provides=frozenset({"stats.file_count"}),
        )
    )
    assert info.cacheable is False


def test_optional_attributes_are_read() -> None:
    info = describe_stage(
        make(
            version="2.1-rc1",
            category=StageCategory.REPORT,
            optional_requires=frozenset({"findings"}),
            parallel_safe=False,
            timeout_seconds=30,
            config_sections=("reporting",),
        )
    )
    assert info.version == "2.1-rc1"
    assert info.optional_requires == frozenset({"findings"})
    assert info.parallel_safe is False
    assert info.timeout_seconds == 30
    assert info.config_sections == ("reporting",)


def test_missing_members() -> None:
    class Nameless:
        pass

    with pytest.raises(StageDeclarationError):
        describe_stage(Nameless())


keys = st.from_regex(r"[a-z][a-z0-9_]{0,10}(\.[a-z][a-z0-9_]{0,10}){0,2}", fullmatch=True)


@given(
    name=st.from_regex(r"[a-z][a-z0-9-]{0,47}", fullmatch=True),
    requires=st.frozensets(keys, max_size=4),
    provides=st.frozensets(keys, min_size=1, max_size=4),
    category=st.sampled_from([*StageCategory, None]),
)
def test_property_deterministic(
    name: str,
    requires: frozenset[str],
    provides: frozenset[str],
    category: StageCategory | None,
) -> None:
    provides = provides - requires or frozenset({"only.output"}) - requires
    stage = make(name=name, requires=requires - provides, provides=provides, category=category)
    first = describe_stage(stage)
    assert first == describe_stage(stage)
    assert first.requires == requires - provides
    assert first.provides == provides
    assert first.name == name
