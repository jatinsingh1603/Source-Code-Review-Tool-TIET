from typing import ClassVar

import pytest
from pydantic import ValidationError

from codekavach.core.models import DataClassification, KavachModel, VersionedModel


class Inner(KavachModel):
    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    value: int


class Outer(KavachModel):
    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    id: str
    inner: Inner
    items: tuple[int, ...]
    positive: int

    def model_post_init(self, context: object, /) -> None:
        if self.positive <= 0:
            raise ValueError("positive must be greater than zero")


class Plain(KavachModel):
    n: int


class Doc(VersionedModel):
    SCHEMA_VERSION: ClassVar[int] = 2

    title: str


def _outer() -> Outer:
    return Outer(id="scan_01", inner=Inner(value=1), items=(1, 2), positive=1)


def test_instances_are_frozen() -> None:
    model = _outer()
    with pytest.raises(ValidationError, match="frozen"):
        model.positive = 2  # type: ignore[misc]  # testing the runtime guard


def test_unknown_keyword_rejected() -> None:
    with pytest.raises(ValidationError):
        Plain(n=1, unknown=2)  # type: ignore[call-arg]  # testing extra="forbid"


def test_evolve_validates_where_model_copy_does_not() -> None:
    model = _outer()
    unchecked = model.model_copy(update={"positive": -5})
    assert unchecked.positive == -5
    with pytest.raises(ValidationError):
        model.evolve(positive=-5)


def test_evolve_keeps_nested_model_and_tuple() -> None:
    model = _outer()
    changed = model.evolve(items=(3,), inner=Inner(value=9))
    assert changed.items == (3,)
    assert changed.inner == Inner(value=9)
    assert isinstance(changed.inner, Inner)
    assert model.items == (1, 2)
    unchanged = model.evolve(positive=4)
    assert unchanged.inner is not None
    assert unchanged.inner.value == 1


def test_error_text_does_not_echo_input() -> None:
    canary = "CANARY_9f3a"
    with pytest.raises(ValidationError) as info:
        Plain(n=canary)  # type: ignore[arg-type]  # deliberately wrong type
    assert canary not in str(info.value)
    assert canary not in repr(info.value.errors(include_input=False))


def test_data_classification_values() -> None:
    assert [member.value for member in DataClassification] == [
        "raw",
        "sanitised",
        "untrusted",
        "metadata",
    ]


def test_data_classification_default_and_override() -> None:
    assert KavachModel.DATA_CLASSIFICATION is DataClassification.RAW
    assert Plain.DATA_CLASSIFICATION is DataClassification.RAW
    assert Inner.DATA_CLASSIFICATION is DataClassification.METADATA
    assert "DATA_CLASSIFICATION" not in Inner.model_fields
    assert "DATA_CLASSIFICATION" not in Inner(value=1).model_dump()
    assert "DATA_CLASSIFICATION" not in str(Inner.model_json_schema())


def test_log_ref() -> None:
    assert _outer().log_ref() == "Outer scan_01"
    assert Plain(n=1).log_ref() == "Plain"


def test_versioned_fills_default() -> None:
    doc = Doc(title="x")
    assert doc.schema_version == 2
    assert '"schema_version":2' in doc.model_dump_json()


@pytest.mark.parametrize("version", [1, 3])
def test_versioned_rejects_other_versions(version: int) -> None:
    with pytest.raises(ValidationError, match="load_versioned"):
        Doc.model_validate({"title": "x", "schema_version": version})


def test_versioned_schema_carries_version() -> None:
    assert Doc.model_json_schema()["x-schema-version"] == 2


def test_versioned_default_in_schema_matches_class() -> None:
    schema = Doc.model_json_schema()
    assert schema["properties"]["schema_version"]["default"] == 2
