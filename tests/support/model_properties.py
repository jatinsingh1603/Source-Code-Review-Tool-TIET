"""Reusable model property checks P1 to P8 (E02-27).

Each ``check_pN(model_cls, instance)`` raises ``AssertionError`` when the property does not
hold, including when the model raises instead (a failed load is a failed round trip). Later
epics call these for their own models; ``check_all`` runs every property.
"""

import copy
import functools
import json
from collections.abc import Callable, Iterator
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import BaseModel

from codekavach.core.models.base import KavachModel, VersionedModel
from codekavach.core.models.canonical import canonical_json
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.migrate import load_versioned
from codekavach.core.models.payload import SanitisedPayload


def _fail(prop: str, model_cls: type[BaseModel], error: Exception) -> AssertionError:
    return AssertionError(f"{prop} failed for {model_cls.__name__}: {type(error).__name__}")


def check_p1(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P1 JSON round trip: ``validate_json(dump_json(m)) == m``."""
    try:
        loaded = model_cls.model_validate_json(instance.model_dump_json())
    except Exception as error:
        raise _fail("P1", model_cls, error) from error
    assert loaded == instance, f"P1: {model_cls.__name__} changed in a JSON round trip"


def check_p2(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P2 Python round trip: ``validate(dump(m)) == m``."""
    try:
        loaded = model_cls.model_validate(instance.model_dump())
    except Exception as error:
        raise _fail("P2", model_cls, error) from error
    assert loaded == instance, f"P2: {model_cls.__name__} changed in a Python round trip"


def check_p3(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P3 idempotent serialisation: dumping a reloaded instance gives the same bytes."""
    first = instance.model_dump_json()
    try:
        second = model_cls.model_validate_json(first).model_dump_json()
    except Exception as error:
        raise _fail("P3", model_cls, error) from error
    assert first == second, f"P3: {model_cls.__name__} serialises differently after a reload"


def _has_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_float(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_float(item) for item in value)
    return False


def check_p4(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P4 canonical stability: canonical JSON and embedded hashes survive a round trip."""
    try:
        loaded = model_cls.model_validate_json(instance.model_dump_json())
    except Exception as error:
        raise _fail("P4", model_cls, error) from error
    if not _has_float(instance.model_dump(mode="json")):
        assert canonical_json(instance) == canonical_json(loaded), (
            f"P4: canonical JSON of {model_cls.__name__} changed in a round trip"
        )
    if isinstance(instance, EgressRecord) and isinstance(loaded, EgressRecord):
        assert loaded.compute_entry_hash() == instance.entry_hash, "P4: entry_hash changed"
    if isinstance(instance, SanitisedPayload) and isinstance(loaded, SanitisedPayload):
        assert loaded.payload_hash == instance.payload_hash, "P4: payload_hash changed"


@functools.cache
def _validator(model_cls: type[BaseModel]) -> Draft202012Validator:
    schema = model_cls.model_json_schema(mode="serialization")
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def check_p5(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P5 schema conformance: the JSON dump validates against the serialisation schema."""
    errors = sorted(
        _validator(model_cls).iter_errors(instance.model_dump(mode="json")),
        key=lambda error: list(error.absolute_path),
    )
    assert not errors, (
        f"P5: {model_cls.__name__} does not match its schema at "
        f"{'/'.join(str(part) for part in errors[0].absolute_path) or '<root>'}: "
        f"{errors[0].validator}"
    )


def _walk(value: Any, where: str) -> Iterator[str]:
    if isinstance(value, list | dict | set | bytearray):
        yield f"{where} is a {type(value).__name__}"
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from _walk(getattr(value, name), f"{where}.{name}")
    elif isinstance(value, tuple | frozenset):
        for index, item in enumerate(value):
            yield from _walk(item, f"{where}[{index}]")


def check_p6(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P6 immutability: fields cannot be assigned and hold no mutable containers."""
    for name in model_cls.model_fields:
        try:
            setattr(instance, name, getattr(instance, name))
        except Exception:  # noqa: BLE001, S112 - any refusal proves immutability
            continue
        raise AssertionError(f"P6: {model_cls.__name__}.{name} can be assigned")
    mutable = list(_walk(instance, model_cls.__name__))
    assert not mutable, f"P6: mutable container: {mutable[0]}"


def check_p7(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P7 hashability: ``hash(m)`` works and equal copies hash equally."""
    try:
        value = hash(instance)
        duplicate = copy.deepcopy(instance)
        other = hash(duplicate)
    except TypeError as error:
        raise _fail("P7", model_cls, error) from error
    if duplicate == instance:
        assert value == other, f"P7: equal {model_cls.__name__} copies hash differently"


def check_p8(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """P8 versioned load: ``load_versioned`` returns the instance; v1 documents may omit it."""
    if not issubclass(model_cls, VersionedModel) or not model_cls.MIGRATABLE:
        return
    document = instance.model_dump_json()
    try:
        assert load_versioned(model_cls, document) == instance, (
            f"P8: load_versioned changed {model_cls.__name__}"
        )
        if model_cls.SCHEMA_VERSION == 1:
            data = json.loads(document)
            data.pop("schema_version", None)
            assert load_versioned(model_cls, data) == instance, (
                f"P8: {model_cls.__name__} without schema_version did not load as version 1"
            )
    except AssertionError:
        raise
    except Exception as error:
        raise _fail("P8", model_cls, error) from error


CHECKS: dict[str, Callable[[type[KavachModel], KavachModel], None]] = {
    "p1": check_p1,
    "p2": check_p2,
    "p3": check_p3,
    "p4": check_p4,
    "p5": check_p5,
    "p6": check_p6,
    "p7": check_p7,
    "p8": check_p8,
}


def check_all(model_cls: type[KavachModel], instance: KavachModel) -> None:
    """Run P1 to P8."""
    for check in CHECKS.values():
        check(model_cls, instance)
