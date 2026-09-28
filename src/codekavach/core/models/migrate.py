"""Schema-version migrations of persisted documents (ADR from E02-01, decision D7).

Owning epic: E02.

``VersionedModel`` refuses documents of another schema version. This module registers per-model
upgrade steps (``from_version`` to ``from_version + 1``) and ``load_versioned`` applies them in
order before validating in JSON mode. Migration functions live next to their model, are pure,
never log their input and perform no I/O: stored documents may contain raw client code.

Hash-bearing models (``MIGRATABLE = False``, for example ``EgressRecord``) are never rewritten;
their readers keep the old class under a versioned name instead. The rules for changing a model
are in ``docs/reference/model-versioning.md``.
"""

import copy
import json
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from typing import Any

from codekavach.core.models.base import VersionedModel
from codekavach.core.models.errors import MigrationError, UnsupportedSchemaVersion

MigrationFn = Callable[[dict[str, Any]], dict[str, Any]]

_REGISTRY: dict[tuple[type[VersionedModel], int], MigrationFn] = {}


def register_migration(
    model: type[VersionedModel], from_version: int
) -> Callable[[MigrationFn], MigrationFn]:
    """Register the step that upgrades ``model`` documents from ``from_version`` by one.

    Raises:
        MigrationError: the step is already registered, or ``from_version`` is out of range.
    """
    if isinstance(from_version, bool) or from_version < 1:
        raise MigrationError(f"{model.__name__}: from_version must be an int of at least 1")
    if from_version >= model.SCHEMA_VERSION:
        raise MigrationError(
            f"{model.__name__}: no step from version {from_version}, the current version is "
            f"{model.SCHEMA_VERSION}"
        )

    def decorate(function: MigrationFn) -> MigrationFn:
        key = (model, from_version)
        if key in _REGISTRY:
            raise MigrationError(
                f"{model.__name__}: a migration from version {from_version} is already registered"
            )
        _REGISTRY[key] = function
        return function

    return decorate


@contextmanager
def temporary_registry() -> Iterator[None]:
    """Snapshot the registry and restore it on exit (for tests)."""
    saved = dict(_REGISTRY)
    try:
        yield
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(saved)


def _version_of(model: type[VersionedModel], data: dict[str, Any]) -> int:
    found = data.get("schema_version", 1)
    if isinstance(found, bool) or not isinstance(found, int):
        raise MigrationError(
            f"{model.__name__}: schema_version must be an integer, not {type(found).__name__}"
        )
    if found < 1:
        raise MigrationError(f"{model.__name__}: schema_version must be at least 1")
    if found > model.SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            f"{model.__name__} schema version {found} was written by a newer CodeKavach "
            f"(this release supports {model.SCHEMA_VERSION}); upgrade the tool"
        )
    return found


def migrate_document(model: type[VersionedModel], data: dict[str, Any]) -> dict[str, Any]:
    """Upgrade ``data`` step by step to ``model.SCHEMA_VERSION``; the input is never mutated.

    Raises:
        UnsupportedSchemaVersion: the document is newer than this release.
        MigrationError: the version is invalid, a step is missing or fails, or the model is
            not migratable. Messages name the model and versions only, never field values.
    """
    found = _version_of(model, data)
    if found < model.SCHEMA_VERSION and not model.MIGRATABLE:
        raise MigrationError(
            f"{model.__name__} documents are hash-bearing and cannot be migrated from version "
            f"{found} to {model.SCHEMA_VERSION}: rewriting them would break their hash chain. "
            "Read old entries with the versioned class for their schema_version instead"
        )
    current = copy.deepcopy(data)
    while found < model.SCHEMA_VERSION:
        step = _REGISTRY.get((model, found))
        if step is None:
            raise MigrationError(f"{model.__name__}: no migration from version {found}")
        try:
            upgraded = step(copy.deepcopy(current))
        except Exception as error:  # noqa: BLE001 - a failing step must not leak document text
            raise MigrationError(
                f"{model.__name__}: the migration from version {found} failed "
                f"({type(error).__name__})"
            ) from None
        if not isinstance(upgraded, dict):
            raise MigrationError(
                f"{model.__name__}: the migration from version {found} did not return a dict"
            )
        found += 1
        current = {**upgraded, "schema_version": found}
    return current


def _parse(model: type[VersionedModel], raw: str | bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise MigrationError(f"{model.__name__}: the document is not valid JSON") from None
    if not isinstance(data, dict):
        raise MigrationError(f"{model.__name__}: the document's top level is not a JSON object")
    return data


def load_versioned[M: VersionedModel](model: type[M], raw: str | bytes | dict[str, Any]) -> M:
    """Parse, upgrade and validate a stored document of any supported version.

    Validation runs in JSON mode, because stored documents are JSON and some models (for
    example those with ``SanitisedText`` fields) accept their wrapped values only from JSON.

    Raises:
        UnsupportedSchemaVersion: the document is newer than this release.
        MigrationError: the document cannot be parsed or upgraded.
        pydantic.ValidationError: the upgraded document is invalid.
    """
    data = migrate_document(model, _parse(model, raw))
    return model.model_validate_json(json.dumps(data))


def check_migration_completeness(models: Iterable[type[VersionedModel]]) -> list[str]:
    """Human-readable problems: missing steps of migratable models (empty when complete)."""
    problems: list[str] = []
    for model in models:
        if not model.MIGRATABLE:
            continue
        problems.extend(
            f"{model.__module__}.{model.__qualname__}: no migration from version {version}"
            for version in range(1, model.SCHEMA_VERSION)
            if (model, version) not in _REGISTRY
        )
    return problems
