import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core.pipeline import keys
from codekavach.core.pipeline.keys import (
    CATEGORY_BY_DEFAULT_NAME,
    DEFAULT_STAGE_ORDER,
    RAW_CODE_KEYS,
    SANITISED_KEYS,
    default_rank,
    is_multi_provider,
    is_valid_key,
    matches_stage_selector,
)
from codekavach.core.pipeline.stage import StageCategory, StageInfo

CONSTANTS = {
    name: value
    for name, value in vars(keys).items()
    if name.isupper() and isinstance(value, str) and name not in {"KEY_PATTERN", "PARTS_SUFFIX"}
}


def info(name: str = "analyse-taint", category: StageCategory | None = None) -> StageInfo:
    return StageInfo(name=name, requires=frozenset(), provides=frozenset({"x"}), category=category)


def test_default_order_matches_architecture() -> None:
    assert DEFAULT_STAGE_ORDER == (
        "ingest", "parse", "analyse", "aggregate", "privacy-prepare",
        "llm-review", "restore", "rate", "report", "sync",
    )  # fmt: skip


def test_constants_are_valid_and_distinct() -> None:
    assert len(CONSTANTS) == 18  # scan.item_failures added by E04-20
    assert all(is_valid_key(value) for value in CONSTANTS.values())
    assert len(set(CONSTANTS.values())) == len(CONSTANTS)
    assert RAW_CODE_KEYS.isdisjoint(SANITISED_KEYS)
    assert set(CONSTANTS.values()) >= (RAW_CODE_KEYS | SANITISED_KEYS)


def test_category_mapping() -> None:
    assert set(CATEGORY_BY_DEFAULT_NAME) == set(DEFAULT_STAGE_ORDER)
    assert sorted(CATEGORY_BY_DEFAULT_NAME.values()) == sorted(StageCategory)
    with pytest.raises(TypeError):
        CATEGORY_BY_DEFAULT_NAME["x"] = StageCategory.SYNC  # type: ignore[index]


@pytest.mark.parametrize("key", ["candidates.raw", "files", "a1.b_2.c"])
def test_valid_keys(key: str) -> None:
    assert is_valid_key(key)


@pytest.mark.parametrize(
    "key", ["Candidates", "a..b", "../x", "a/b", "", ".a", "a.", "1a", "a" * 65]
)
def test_invalid_keys(key: str) -> None:
    assert not is_valid_key(key)


def test_multi_provider() -> None:
    assert is_multi_provider("candidates.raw")
    assert is_multi_provider("x.parts")
    assert not is_multi_provider("candidates")


@pytest.mark.parametrize(("index", "category"), list(enumerate(StageCategory)))
def test_default_rank(index: int, category: StageCategory) -> None:
    assert default_rank(info(category=category)) == index


def test_default_rank_examples() -> None:
    assert default_rank(info(category=StageCategory.PRIVACY)) == 4
    assert default_rank(info()) == 10


def test_stage_selector() -> None:
    taint = info("analyse-taint", StageCategory.ANALYSE)
    assert matches_stage_selector(taint, "analyse")
    assert matches_stage_selector(taint, "analyse-taint")
    assert not matches_stage_selector(taint, "parse")
    assert not matches_stage_selector(info("analyse-taint"), "analyse")
    assert not matches_stage_selector(taint, "analyse-rules")


@given(
    st.text(max_size=20),
    st.sampled_from(["/", "\\", " ", "A", "Z", ".."]),
    st.text(max_size=20),
)
def test_property_bad_characters_rejected(prefix: str, bad: str, suffix: str) -> None:
    assert not is_valid_key(prefix + bad + suffix)
