from typing import Annotated, Any

import pytest
from pydantic import BaseModel, Field, ValidationError

from codekavach.config.models.base import (
    SectionModel,
    StrList,
    in_range,
    restricted,
    sensitive,
    split_csv,
    union_merge,
    volatile,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a,b", ["a", "b"]),
        (" a , b ", ["a", "b"]),
        ("a,,b", ["a", "b"]),
        ("", []),
        (["a"], ["a"]),
    ],
)
def test_split_csv(value: Any, expected: list[str]) -> None:
    assert split_csv(value) == expected


def test_helpers_combine() -> None:
    assert sensitive() == {"x-ck-sensitive": True}
    assert volatile() == {"x-ck-volatile": True}
    assert union_merge() == {"x-ck-merge": "union"}
    assert restricted() == {"x-ck-restricted": True}
    assert sensitive() | restricted() == {"x-ck-sensitive": True, "x-ck-restricted": True}


class Demo(SectionModel):
    items: StrList = Field(default_factory=list, description="Items.")
    count: int = Field(default=1, description="Count.")


def test_section_conventions() -> None:
    assert Demo.model_validate({"items": "a, b"}).items == ["a", "b"]
    with pytest.raises(ValidationError):
        Demo.model_validate({"unknown": 1})
    demo = Demo()
    with pytest.raises(ValidationError):
        demo.count = 2  # type: ignore[misc]


def test_hidden_input() -> None:
    canary = "CANARY_9f3a"
    with pytest.raises(ValidationError) as info:
        Demo.model_validate({"count": canary})
    assert canary not in str(info.value)


def test_in_range_message_starts_with_code() -> None:
    class Ranged(BaseModel):
        value: Annotated[int, in_range(1, 3, "demo.value")] = 1

    with pytest.raises(ValidationError) as info:
        Ranged(value=9)
    message = str(info.value.errors()[0]["ctx"]["error"])
    assert message == "[CK-CFG-003] demo.value must be between 1 and 3"
