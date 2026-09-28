"""Base classes and data classification for every core model.

Owning epic: E02.
"""

from enum import StrEnum
from typing import Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, model_validator


class DataClassification(StrEnum):
    """What kind of data a model holds; the I2 allow-list (E02-28) is built from it."""

    RAW = "raw"  # client code, paths, identifiers, engine messages, restored text
    SANITISED = "sanitised"  # produced by the privacy layer; may be passed to codekavach.llm
    UNTRUSTED = "untrusted"  # produced by a model; validate before use
    METADATA = "metadata"  # numbers, hashes, ids, enums, taxonomy references; no client names


class KavachModel(BaseModel):
    """Base class of every core model: frozen, strict about extra keys, safe in error text.

    Conventions for subclasses:

    - Sequence fields are ``tuple[T, ...]``, never ``list``: a list inside a frozen model can
      still be mutated in place and makes the instance unhashable.
    - Derived values are plain ``@property`` attributes, never ``@computed_field``, because
      computed fields appear in ``model_dump()`` and would break ``evolve``.
    - Use ``evolve(**changes)`` instead of ``model_copy(update=...)``; the latter does not run
      validators.
    - ``hide_input_in_errors=True`` keeps the offending value out of ``str(ValidationError)``, so
      client code or a secret passed to the wrong field is not printed into logs and tracebacks.
      ``ValidationError.errors()`` still carries the value under ``input``: code that logs or
      stores error details must call ``errors(include_input=False)``.
    - Log statements use ``log_ref()``, never ``repr()``, which prints client data.
    - Every concrete model sets ``DATA_CLASSIFICATION``. The default is ``RAW``, so a model that
      forgets is treated as client data (fail closed).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        allow_inf_nan=False,
        use_enum_values=False,  # keep Enum members in memory, values in JSON
        populate_by_name=True,
        ser_json_timedelta="float",
        hide_input_in_errors=True,  # error text must not echo client code or secrets
    )

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW

    def evolve(self, **changes: object) -> Self:
        """Return a copy with ``changes`` applied, validated like a new instance."""
        return type(self).model_validate({**self.model_dump(), **changes})

    def log_ref(self) -> str:
        """Return a reference safe for logs: the class name and, if present, the ``id``."""
        name = type(self).__name__
        if "id" in type(self).model_fields:
            value = getattr(self, "id", None)
            if isinstance(value, str):
                return f"{name} {value}"
        return name


def _add_schema_version(schema: dict[str, Any], model: type[Any]) -> None:
    schema["x-schema-version"] = model.SCHEMA_VERSION
    field = schema.get("properties", {}).get("schema_version")
    if field is not None:
        field["default"] = model.SCHEMA_VERSION


class VersionedModel(KavachModel):
    """Base class of persisted top-level documents that carry a schema version."""

    model_config = ConfigDict(json_schema_extra=_add_schema_version)

    SCHEMA_VERSION: ClassVar[int] = 1
    # False for hash-bearing documents, which are never rewritten (see models.migrate).
    MIGRATABLE: ClassVar[bool] = True

    # The default only makes the keyword optional for type checkers; the validator below
    # always fills in the subclass's SCHEMA_VERSION when the key is absent.
    schema_version: int = 1

    @model_validator(mode="before")
    @classmethod
    def _check_schema_version(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "schema_version" not in data:
            return {**data, "schema_version": cls.SCHEMA_VERSION}
        found = data["schema_version"]
        if found != cls.SCHEMA_VERSION:
            raise ValueError(
                f"{cls.__name__} schema version {found!r} is not the supported version "
                f"{cls.SCHEMA_VERSION}; load this document with "
                "codekavach.core.models.migrate.load_versioned"
            )
        return data
