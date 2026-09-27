"""The artefact store contract: protocol, canonical encoding, digests and errors.

Owning epic: E04.

Stages exchange data only through the artefact store, which therefore holds client-derived data.
Three safeguards are part of the contract:

- no executable deserialisation: values are JSON envelopes, and the type tag stored with a value is
  compared with the requested model, never imported or evaluated;
- error messages name keys, types and counts, never values (Pydantic error text is not passed on);
- the never-persist marker: an object whose ``__ck_never_persist__`` attribute is truthy (the scan
  salt, vault material) is refused by every ``put``, persisted or transient (I3).

The canonical encoding sorts keys and uses compact separators, so equal values give equal bytes and
equal SHA-256 digests on every platform; the on-disk store (E04-09) reuses it.
"""

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, TypeVar

from pydantic import BaseModel, JsonValue, ValidationError

M = TypeVar("M", bound=BaseModel)
Shape = Literal["model", "list", "json"]
ENVELOPE_VERSION = 1
NEVER_PERSIST_ATTRIBUTE = "__ck_never_persist__"


class ArtefactError(Exception):
    """Base class of artefact store errors."""


class ArtefactMissingError(ArtefactError):
    """No artefact (or no content with that digest) is stored under the key."""


class ArtefactTypeError(ArtefactError):
    """The stored artefact has another shape or type than the one requested."""


class ArtefactSerialisationError(ArtefactError):
    """The value cannot be encoded as an artefact."""


class ArtefactForbiddenError(ArtefactError):
    """The value carries the never-persist marker."""


class ArtefactCorruptError(ArtefactError):
    """Stored bytes do not decode into the requested type."""


class ArtefactKeyError(ArtefactError):
    """A key or part name is invalid, or used with the wrong provider kind."""


@dataclass(frozen=True, slots=True)
class ArtefactRef:
    """Where an artefact's content is: its digest and size, or its parts."""

    key: str
    digest: str | None
    size: int
    parts: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class EncodedArtefact:
    """The canonical bytes of one artefact value."""

    shape: Shape
    type_tag: str
    data: bytes
    digest: str


class ArtefactStore(Protocol):
    """What ``RunContext.store`` offers every stage."""

    def put(self, key: str, value: object, *, persist: bool = True) -> ArtefactRef:
        """Store ``value`` under a single-provider key; last write wins."""

    def put_part(self, key: str, part: str, value: object) -> ArtefactRef:
        """Store one provider's part of a multi-provider key."""

    def get(self, key: str, model: type[M]) -> M:
        """The model stored under ``key``."""

    def get_list(self, key: str, item: type[M]) -> list[M]:
        """The list of models stored under ``key``."""

    def get_json(self, key: str) -> JsonValue:
        """The JSON value stored under ``key``."""

    def get_object(self, key: str) -> object:
        """The transient object stored under ``key``."""

    def get_parts(self, key: str, item: type[M]) -> dict[str, list[M]]:
        """Every part of a multi-provider key, ordered by part name."""

    def has(self, key: str) -> bool:
        """True when ``key`` holds a value (for a multi-provider key, at least one part)."""

    def ref(self, key: str) -> ArtefactRef | None:
        """The reference of ``key``, or ``None``."""

    def bind(self, key: str, ref: ArtefactRef) -> None:
        """Point ``key`` at content that is already stored (a cache hit)."""

    def discard(self, key: str, *, part: str | None = None) -> None:
        """Remove ``key`` or one of its parts; idempotent."""

    def keys(self) -> tuple[str, ...]:
        """Keys that hold a value, sorted."""


def type_tag(cls: type) -> str:
    """``<module>.<qualname>`` of a model class."""
    return f"{cls.__module__}.{cls.__qualname__}"


def check_never_persist(value: object) -> None:
    """Refuse a value, or an item of a top-level list or tuple, carrying the marker."""
    items: Sequence[object] = value if isinstance(value, (list, tuple)) else ()
    for candidate in (value, *items):
        try:
            marked = bool(getattr(candidate, NEVER_PERSIST_ATTRIBUTE, False))
        except Exception:  # noqa: BLE001 - an odd __getattr__ must not let the value through
            marked = True
        if marked:
            raise ArtefactForbiddenError(
                f"a value of type {type(candidate).__name__} must never be stored"
            )


def _check_json(value: object) -> JsonValue:
    """Validate a JSON value (tuples become lists); errors name types, never values."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ArtefactSerialisationError("artefact contains a non-finite float")
        return value
    if isinstance(value, (list, tuple)):
        return [_check_json(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ArtefactSerialisationError(
                    f"artefact dictionary keys must be str, not {type(key).__name__}"
                )
            result[key] = _check_json(item)
        return result
    raise ArtefactSerialisationError(f"cannot store a value of type {type(value).__name__}")


def _shape_of(value: object) -> tuple[Shape, str, Any]:
    if isinstance(value, BaseModel):
        return "model", type_tag(type(value)), value.model_dump(mode="json")
    if isinstance(value, (list, tuple)):
        if not value:
            return "list", "", []
        first = type(value[0])
        if isinstance(value[0], BaseModel):
            if any(type(item) is not first for item in value):
                raise ArtefactSerialisationError(
                    f"a list artefact must hold one model class only, starting {first.__name__}"
                )
            return "list", type_tag(first), [item.model_dump(mode="json") for item in value]
    return "json", "", _check_json(value)


def encode_artefact(value: object) -> EncodedArtefact:
    """The canonical envelope bytes and SHA-256 digest of ``value``.

    Raises:
        ArtefactForbiddenError: the value carries the never-persist marker.
        ArtefactSerialisationError: the value is not a model, a list of one model class or JSON.
    """
    check_never_persist(value)
    shape, tag, data = _shape_of(value)
    envelope = {"ck_artefact": ENVELOPE_VERSION, "shape": shape, "type": tag, "data": data}
    try:
        text = json.dumps(
            envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
    except ValueError:
        raise ArtefactSerialisationError("artefact contains a non-finite float") from None
    raw = text.encode("utf-8")
    return EncodedArtefact(shape, tag, raw, hashlib.sha256(raw).hexdigest())


def parts_digest(parts: Sequence[tuple[str, str]]) -> str:
    """Digest of a multi-provider key: SHA-256 of ``part:digest`` lines sorted by part name."""
    text = "\n".join(f"{name}:{digest}" for name, digest in sorted(parts))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _envelope(key: str, encoded: EncodedArtefact) -> dict[str, Any]:
    try:
        envelope = json.loads(encoded.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ArtefactCorruptError(f"artefact {key!r} is not a valid envelope") from None
    if not isinstance(envelope, dict) or envelope.get("ck_artefact") != ENVELOPE_VERSION:
        raise ArtefactCorruptError(f"artefact {key!r} has an unknown envelope version")
    return envelope


def _validate[T: BaseModel](key: str, model: type[T], data: object) -> T:
    try:
        return model.model_validate(data)
    except ValidationError as error:
        raise ArtefactCorruptError(
            f"artefact {key!r} does not validate as {model.__name__} ({error.error_count()} errors)"
        ) from None


def decode_model[T: BaseModel](key: str, encoded: EncodedArtefact, model: type[T]) -> T:
    """Decode a ``model`` artefact after comparing its type tag."""
    envelope = _envelope(key, encoded)
    if envelope.get("shape") != "model":
        raise ArtefactTypeError(f"artefact {key!r} is a {envelope.get('shape')}, not a model")
    if envelope.get("type") != type_tag(model):
        raise ArtefactTypeError(
            f"artefact {key!r} holds {envelope.get('type')}, requested {type_tag(model)}"
        )
    return _validate(key, model, envelope.get("data"))


def decode_list[T: BaseModel](key: str, encoded: EncodedArtefact, item: type[T]) -> list[T]:
    """Decode a ``list`` artefact (an empty list matches any item type)."""
    envelope = _envelope(key, encoded)
    if envelope.get("shape") != "list":
        raise ArtefactTypeError(f"artefact {key!r} is a {envelope.get('shape')}, not a list")
    data = envelope.get("data")
    if not isinstance(data, list):
        raise ArtefactCorruptError(f"artefact {key!r} list data is not a list")
    if not data:
        return []
    if envelope.get("type") != type_tag(item):
        raise ArtefactTypeError(
            f"artefact {key!r} holds {envelope.get('type')}, requested {type_tag(item)}"
        )
    return [_validate(key, item, entry) for entry in data]


def decode_json(key: str, encoded: EncodedArtefact) -> JsonValue:
    """Decode the data of any persisted artefact as a JSON value."""
    data: JsonValue = _envelope(key, encoded).get("data")
    return data
