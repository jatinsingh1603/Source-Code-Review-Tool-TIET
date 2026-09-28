"""A stage's restricted, revocable view of the artefact store (ADR-0007 D4 and D8).

Owning epic: E04.

Every stage gets a ``StageScopedStore`` instead of the shared store:

- reads are limited to ``requires | optional_requires | provides``;
- writes are limited to ``provides``, a multi-provider part is always named after the stage, and
  a transient key must be written with ``persist=False`` (any other key with ``persist=True``);
- ``bind`` and ``bind_part`` (serving a cache hit) are reserved for the orchestrator;
- after ``revoke()`` every call raises ``StageRevokedError``. The revocation check and the
  delegated call happen under one lock, so no write lands after ``revoke()`` has returned.

Declarations therefore hold by construction (cache keys computed from declared inputs are sound),
an LLM-category stage cannot read raw-code artefacts through the pipeline API (run-time support
for I2), and a timed-out stage thread cannot alter the store afterwards (I4).

This is not a sandbox: a stage is Python code in the same process and can import anything.
Plugin code is trusted code. Error messages name stages and keys only, never values.
"""

import threading
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel, JsonValue

from codekavach.core.pipeline.keys import is_multi_provider
from codekavach.core.store.base import (
    ArtefactError,
    ArtefactKeyError,
    ArtefactRef,
    ArtefactStore,
    ArtefactTypeError,
    check_never_persist,
)

if TYPE_CHECKING:
    from codekavach.core.pipeline.stage import StageInfo

M = TypeVar("M", bound=BaseModel)


class UndeclaredAccessError(ArtefactKeyError):
    """A stage used a key it did not declare for that kind of access (an ``ArtefactError``)."""

    def __init__(self, stage: str, key: str, operation: str) -> None:
        self.stage = stage
        self.key = key
        self.operation = operation
        super().__init__(f"stage {stage!r} may not {operation} {key!r}")


class StageRevokedError(ArtefactError):
    """The stage's view of the store was revoked (the stage ended, timed out or was cancelled)."""

    def __init__(self, stage: str) -> None:
        self.stage = stage
        super().__init__(f"stage {stage!r} can no longer use the artefact store")


class StageScopedStore:
    """The ``ArtefactStore`` a stage sees: its declared keys only, until revoked."""

    def __init__(self, inner: ArtefactStore, info: "StageInfo") -> None:
        self._inner = inner
        self._info = info
        self._readable = info.requires | info.optional_requires | info.provides
        self._lock = threading.Lock()
        self._revoked = False

    @property
    def revoked(self) -> bool:
        """True once ``revoke()`` has been called."""
        return self._revoked

    def revoke(self) -> None:
        """End the stage's access; every later call raises ``StageRevokedError``."""
        with self._lock:
            self._revoked = True

    def _check_open(self) -> None:
        if self._revoked:
            raise StageRevokedError(self._info.name)

    def _check_read(self, key: str) -> None:
        self._check_open()
        if key not in self._readable:
            raise UndeclaredAccessError(self._info.name, key, "read")

    def _check_write(self, key: str) -> None:
        self._check_open()
        if key not in self._info.provides:
            raise UndeclaredAccessError(self._info.name, key, "write")

    # writes

    def put(self, key: str, value: object, *, persist: bool = True) -> ArtefactRef:
        """Store a declared output; transient keys need ``persist=False``, others ``True``."""
        with self._lock:
            self._check_write(key)
            check_never_persist(value)  # the same refusal as the inner store, whatever the flag
            transient = key in self._info.transient_provides
            if transient == persist:
                expected = "persist=False" if transient else "persist=True"
                raise ArtefactTypeError(f"artefact {key!r} must be written with {expected}")
            return self._inner.put(key, value, persist=persist)

    def put_part(self, key: str, part: str, value: object) -> ArtefactRef:
        """Store the stage's own part of a declared multi-provider output."""
        with self._lock:
            self._check_write(key)
            if part != self._info.name:
                raise UndeclaredAccessError(self._info.name, f"{key}[{part}]", "write")
            return self._inner.put_part(key, part, value)

    def discard(self, key: str, *, part: str | None = None) -> None:
        """Remove a declared output; for a multi-provider key only the stage's own part."""
        with self._lock:
            self._check_write(key)
            if is_multi_provider(key):
                if part not in (None, self._info.name):
                    raise UndeclaredAccessError(self._info.name, f"{key}[{part}]", "write")
                part = self._info.name
            self._inner.discard(key, part=part)

    def bind(self, key: str, ref: ArtefactRef) -> None:
        """Not available to stages: only the orchestrator serves cache hits."""
        with self._lock:
            self._check_open()
            raise UndeclaredAccessError(self._info.name, key, "bind")

    def bind_part(self, key: str, part: str, digest: str) -> None:
        """Not available to stages: only the orchestrator serves cache hits."""
        with self._lock:
            self._check_open()
            raise UndeclaredAccessError(self._info.name, f"{key}[{part}]", "bind")

    # reads

    def get(self, key: str, model: type[M]) -> M:
        """The model stored under a readable key."""
        with self._lock:
            self._check_read(key)
            return self._inner.get(key, model)

    def get_list(self, key: str, item: type[M]) -> list[M]:
        """The list of models stored under a readable key."""
        with self._lock:
            self._check_read(key)
            return self._inner.get_list(key, item)

    def get_json(self, key: str) -> JsonValue:
        """The JSON value stored under a readable key."""
        with self._lock:
            self._check_read(key)
            return self._inner.get_json(key)

    def get_object(self, key: str) -> object:
        """The transient object stored under a readable key."""
        with self._lock:
            self._check_read(key)
            return self._inner.get_object(key)

    def get_parts(self, key: str, item: type[M]) -> dict[str, list[M]]:
        """Every part of a readable multi-provider key, ordered by part name."""
        with self._lock:
            self._check_read(key)
            return self._inner.get_parts(key, item)

    def has(self, key: str) -> bool:
        """True when a readable key holds a value."""
        with self._lock:
            self._check_read(key)
            return self._inner.has(key)

    def ref(self, key: str) -> ArtefactRef | None:
        """The reference of a readable key, or ``None``."""
        with self._lock:
            self._check_read(key)
            return self._inner.ref(key)

    def keys(self) -> tuple[str, ...]:
        """The readable keys that hold a value, sorted."""
        with self._lock:
            self._check_open()
            stored = self._inner.keys()  # a store, not a dict
            return tuple(key for key in stored if key in self._readable)
