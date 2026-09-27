"""An in-memory artefact store for unit tests and for stages' own tests.

Owning epic: E04.

Persisted values are kept in their canonical encoded form and decoded on every read, so a test
that passes against this store also passes against the on-disk store (E04-09). Transient values
are kept as Python objects and are readable only through ``get_object``. One re-entrant lock
serialises every operation.
"""

import re
import threading

from pydantic import JsonValue

from codekavach.core.pipeline.keys import is_multi_provider, is_valid_key
from codekavach.core.store.base import (
    ArtefactKeyError,
    ArtefactMissingError,
    ArtefactRef,
    ArtefactTypeError,
    EncodedArtefact,
    M,
    check_never_persist,
    decode_json,
    decode_list,
    decode_model,
    encode_artefact,
    parts_digest,
)

PART_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,47}$")


def check_key(key: object) -> str:
    """Raise ``ArtefactKeyError`` unless ``key`` is a valid artefact key."""
    if not isinstance(key, str) or not is_valid_key(key):
        raise ArtefactKeyError(f"invalid artefact key {key!r}")
    return key


def check_part(part: object) -> str:
    """Raise ``ArtefactKeyError`` unless ``part`` is a valid part (stage) name."""
    if not isinstance(part, str) or not PART_PATTERN.match(part):
        raise ArtefactKeyError(f"invalid part name {part!r}")
    return part


def single_key(key: object) -> str:
    """A valid single-provider key, else ``ArtefactKeyError``."""
    checked = check_key(key)
    if is_multi_provider(checked):
        raise ArtefactKeyError(f"artefact key {checked!r} is multi-provider; use put_part")
    return checked


def multi_key(key: object) -> str:
    """A valid multi-provider key, else ``ArtefactKeyError``."""
    checked = check_key(key)
    if not is_multi_provider(checked):
        raise ArtefactKeyError(f"artefact key {checked!r} is single-provider; use put")
    return checked


class InMemoryArtefactStore:
    """A complete, thread-safe ``ArtefactStore`` held in memory."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._content: dict[str, EncodedArtefact] = {}
        self._single: dict[str, str] = {}
        self._transient: dict[str, object] = {}
        self._parts: dict[str, dict[str, str]] = {}

    def _store(self, encoded: EncodedArtefact) -> None:
        self._content.setdefault(encoded.digest, encoded)

    def put(self, key: str, value: object, *, persist: bool = True) -> ArtefactRef:
        """Store ``value``; with ``persist=False`` keep the object itself (transient)."""
        single_key(key)
        if not persist:
            check_never_persist(value)
            with self._lock:
                self._single.pop(key, None)
                self._transient[key] = value
            return ArtefactRef(key=key, digest=None, size=0)
        encoded = encode_artefact(value)
        with self._lock:
            self._store(encoded)
            self._transient.pop(key, None)
            self._single[key] = encoded.digest
        return ArtefactRef(key=key, digest=encoded.digest, size=len(encoded.data))

    def put_part(self, key: str, part: str, value: object) -> ArtefactRef:
        """Store one part of a multi-provider key."""
        multi_key(key)
        check_part(part)
        encoded = encode_artefact(value)
        with self._lock:
            self._store(encoded)
            parts = self._parts.setdefault(key, {})
            parts[part] = encoded.digest
            ordered = tuple(sorted(parts.items()))
            size = sum(len(self._content[digest].data) for _, digest in ordered)
        return ArtefactRef(key=key, digest=parts_digest(ordered), size=size, parts=ordered)

    def _encoded(self, key: str) -> EncodedArtefact:
        check_key(key)
        with self._lock:
            if key in self._transient:
                raise ArtefactTypeError(f"artefact {key!r} is transient; use get_object")
            digest = self._single.get(key)
            if digest is None:
                raise ArtefactMissingError(f"no artefact {key!r}")
            return self._content[digest]

    def get(self, key: str, model: type[M]) -> M:
        """The model stored under ``key``."""
        return decode_model(key, self._encoded(key), model)

    def get_list(self, key: str, item: type[M]) -> list[M]:
        """The list of models stored under ``key``."""
        return decode_list(key, self._encoded(key), item)

    def get_json(self, key: str) -> JsonValue:
        """The JSON data stored under ``key``."""
        return decode_json(key, self._encoded(key))

    def get_object(self, key: str) -> object:
        """The transient object stored under ``key``."""
        check_key(key)
        with self._lock:
            if key in self._transient:
                return self._transient[key]
            if key in self._single or key in self._parts:
                raise ArtefactTypeError(f"artefact {key!r} is persisted; use a typed getter")
        raise ArtefactMissingError(f"no artefact {key!r}")

    def get_parts(self, key: str, item: type[M]) -> dict[str, list[M]]:
        """Every part of ``key``, ordered by part name."""
        multi_key(key)
        with self._lock:
            parts = sorted(self._parts.get(key, {}).items())
            encoded = [(name, self._content[digest]) for name, digest in parts]
        if not encoded:
            raise ArtefactMissingError(f"no artefact {key!r}")
        result: dict[str, list[M]] = {}
        for name, value in encoded:
            if value.shape == "model":
                result[name] = [decode_model(f"{key}/{name}", value, item)]
            else:
                result[name] = decode_list(f"{key}/{name}", value, item)
        return result

    def has(self, key: str) -> bool:
        """True when ``key`` holds a value or at least one part."""
        check_key(key)
        with self._lock:
            return key in self._single or key in self._transient or bool(self._parts.get(key))

    def ref(self, key: str) -> ArtefactRef | None:
        """The reference of ``key``, or ``None`` when it holds nothing."""
        check_key(key)
        with self._lock:
            if key in self._transient:
                return ArtefactRef(key=key, digest=None, size=0)
            if key in self._single:
                digest = self._single[key]
                return ArtefactRef(key=key, digest=digest, size=len(self._content[digest].data))
            parts = tuple(sorted(self._parts.get(key, {}).items()))
            if not parts:
                return None
            size = sum(len(self._content[digest].data) for _, digest in parts)
            return ArtefactRef(key=key, digest=parts_digest(parts), size=size, parts=parts)

    def bind(self, key: str, ref: ArtefactRef) -> None:
        """Point ``key`` at stored content named by ``ref`` (digest or parts)."""
        check_key(key)
        with self._lock:
            if ref.parts:
                multi_key(key)
                for part, digest in ref.parts:
                    check_part(part)
                    if digest not in self._content:
                        raise ArtefactMissingError(f"no stored content for part {part!r}")
                self._parts[key] = dict(ref.parts)
                return
            single_key(key)
            if ref.digest is None or ref.digest not in self._content:
                raise ArtefactMissingError(f"no stored content for artefact {key!r}")
            self._transient.pop(key, None)
            self._single[key] = ref.digest

    def discard(self, key: str, *, part: str | None = None) -> None:
        """Remove ``key`` or one part of it; removing something absent is not an error."""
        check_key(key)
        with self._lock:
            if part is None:
                self._single.pop(key, None)
                self._transient.pop(key, None)
                self._parts.pop(key, None)
                return
            check_part(part)
            parts = self._parts.get(key)
            if parts is not None:
                parts.pop(part, None)
                if not parts:
                    del self._parts[key]

    def keys(self) -> tuple[str, ...]:
        """Keys that hold a value, sorted."""
        with self._lock:
            return tuple(sorted({*self._single, *self._transient, *self._parts}))
