import importlib
import inspect
import json
import pkgutil
from collections.abc import Iterator
from typing import Any, ClassVar

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.core import models
from codekavach.core.models import VersionedModel
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.errors import MigrationError, UnsupportedSchemaVersion
from codekavach.core.models.migrate import (
    check_migration_completeness,
    load_versioned,
    migrate_document,
    register_migration,
    temporary_registry,
)
from codekavach.core.models.payload import SanitisedPayload
from tests.support.factories import make_egress_chain, make_payload

SECRET_TEXT = "CANARY_doc_text_7731"  # pragma: allowlist secret


class Widget(VersionedModel):
    SCHEMA_VERSION: ClassVar[int] = 3

    title: str
    colour: str


class Gadget(VersionedModel):
    SCHEMA_VERSION: ClassVar[int] = 2

    size: int
    tags: tuple[str, ...] = ()


class Frozen(VersionedModel):
    SCHEMA_VERSION: ClassVar[int] = 2
    MIGRATABLE: ClassVar[bool] = False

    value: int


@pytest.fixture(autouse=True)
def registry() -> Iterator[None]:
    with temporary_registry():

        @register_migration(Widget, 1)
        def rename(data: dict[str, Any]) -> dict[str, Any]:
            data["title"] = data.pop("name")
            return data

        @register_migration(Widget, 2)
        def add_colour(data: dict[str, Any]) -> dict[str, Any]:
            return {**data, "colour": "unknown"}

        @register_migration(Gadget, 1)
        def identity(data: dict[str, Any]) -> dict[str, Any]:
            return data

        yield


def test_widget_upgrades() -> None:
    expected = Widget(title="w", colour="unknown")
    assert load_versioned(Widget, {"name": "w"}) == expected
    assert load_versioned(Widget, {"name": "w", "schema_version": 1}) == expected
    assert load_versioned(Widget, {"title": "w", "schema_version": 2}) == expected
    current = {"title": "w", "colour": "red", "schema_version": 3}
    assert load_versioned(Widget, current) == Widget(title="w", colour="red")
    assert expected.schema_version == 3


def test_input_kinds() -> None:
    document = {"name": "w", "schema_version": 1}
    text = json.dumps(document)
    assert (
        load_versioned(Widget, text)
        == load_versioned(Widget, text.encode())
        == (load_versioned(Widget, document))
    )


def test_newer_version_is_unsupported() -> None:
    with pytest.raises(UnsupportedSchemaVersion, match="newer CodeKavach"):
        load_versioned(Widget, {"title": "w", "colour": "c", "schema_version": 4})


def test_missing_step_names_model_and_version() -> None:
    class Lonely(VersionedModel):
        SCHEMA_VERSION: ClassVar[int] = 2

    with pytest.raises(MigrationError, match="Lonely: no migration from version 1"):
        load_versioned(Lonely, {"schema_version": 1})


def test_duplicate_and_invalid_registration() -> None:
    with pytest.raises(MigrationError, match="already registered"):
        register_migration(Widget, 1)(lambda data: data)
    with pytest.raises(MigrationError, match="current version"):
        register_migration(Widget, 3)
    with pytest.raises(MigrationError, match="at least 1"):
        register_migration(Widget, 0)


def test_models_with_the_same_name_do_not_collide() -> None:
    first = Widget

    class Widget2(VersionedModel):
        SCHEMA_VERSION: ClassVar[int] = 2

    Widget2.__name__ = Widget2.__qualname__ = "Widget"
    register_migration(Widget2, 1)(lambda data: data)
    assert first.__name__ == Widget2.__name__
    assert check_migration_completeness([first, Widget2]) == []


def test_mutating_migration_does_not_affect_caller() -> None:
    document = {"name": "w", "schema_version": 1, "nested": {"keep": [1]}}
    snapshot = json.loads(json.dumps(document))
    upgraded = migrate_document(Widget, document)
    assert document == snapshot
    assert upgraded["schema_version"] == 3


@pytest.mark.parametrize("version", [True, 1.0, "1", 0, -1, None, [1]])
def test_bad_schema_versions(version: object) -> None:
    with pytest.raises(MigrationError) as info:
        load_versioned(Widget, {"name": SECRET_TEXT, "schema_version": version})
    assert SECRET_TEXT not in str(info.value)


@pytest.mark.parametrize(
    "raw", [f'{{"name": "{SECRET_TEXT}"', f"[{SECRET_TEXT!r}]", "[1]", b"\xff"]
)
def test_bad_json_hides_the_document(raw: str | bytes) -> None:
    with pytest.raises(MigrationError) as info:
        load_versioned(Widget, raw)
    assert SECRET_TEXT not in str(info.value)


def test_failing_step_hides_the_document() -> None:
    with pytest.raises(MigrationError, match="migration from version 1 failed") as info:
        load_versioned(Widget, {"wrong": SECRET_TEXT, "schema_version": 1})
    assert SECRET_TEXT not in str(info.value)


def test_step_must_return_a_dict() -> None:
    class Bad(VersionedModel):
        SCHEMA_VERSION: ClassVar[int] = 2

    register_migration(Bad, 1)(lambda data: None)  # type: ignore[arg-type,return-value]
    with pytest.raises(MigrationError, match="did not return a dict"):
        load_versioned(Bad, {})


def test_non_migratable_models(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(MigrationError, match="hash-bearing"):
        load_versioned(Frozen, {"value": 1, "schema_version": 1})
    assert load_versioned(Frozen, {"value": 1, "schema_version": 2}) == Frozen(value=1)
    record = make_egress_chain(1)[0]
    assert load_versioned(EgressRecord, record.model_dump_json()) == record
    monkeypatch.setattr(EgressRecord, "SCHEMA_VERSION", 2)
    with pytest.raises(MigrationError, match="hash chain"):
        load_versioned(EgressRecord, record.model_dump(mode="json"))


def test_sanitised_text_loads_through_json_mode() -> None:
    payload = make_payload()
    assert load_versioned(SanitisedPayload, payload.model_dump_json()) == payload


def test_completeness_check() -> None:
    class Incomplete(VersionedModel):
        SCHEMA_VERSION: ClassVar[int] = 3

    register_migration(Incomplete, 2)(lambda data: data)
    problems = check_migration_completeness([Widget, Gadget, Frozen, Incomplete])
    assert len(problems) == 1
    assert problems[0].endswith("Incomplete: missing migration step 1 -> 2")


def test_real_models_are_complete() -> None:
    real = {
        value
        for info in pkgutil.iter_modules(models.__path__, "codekavach.core.models.")
        for value in vars(importlib.import_module(info.name)).values()
        if inspect.isclass(value)
        and issubclass(value, VersionedModel)
        and value.__module__.startswith("codekavach.")
    }
    assert {EgressRecord, SanitisedPayload} <= real
    assert check_migration_completeness(real) == []


def test_temporary_registry_restores() -> None:
    with temporary_registry():
        register_migration(Gadget, 1)  # the outer fixture's step is still registered
    with pytest.raises(MigrationError, match="already registered"):
        register_migration(Gadget, 1)(lambda data: data)


def test_registry_is_restored_after_leaving() -> None:
    class Temporary(VersionedModel):
        SCHEMA_VERSION: ClassVar[int] = 2

    with temporary_registry():
        register_migration(Temporary, 1)(lambda data: data)
        assert check_migration_completeness([Temporary]) == []
    assert check_migration_completeness([Temporary]) != []


@given(st.text(max_size=20), st.text(max_size=10))
def test_widget_round_trip(title: str, colour: str) -> None:
    with temporary_registry():
        doc = Widget(title=title, colour=colour)
        assert load_versioned(Widget, doc.model_dump_json()) == doc


@given(st.integers(), st.lists(st.text(max_size=5), max_size=4).map(tuple))
def test_gadget_round_trip(size: int, tags: tuple[str, ...]) -> None:
    doc = Gadget(size=size, tags=tags)
    assert load_versioned(Gadget, doc.model_dump_json()) == doc
    assert load_versioned(Gadget, doc.model_dump_json().encode()) == doc
