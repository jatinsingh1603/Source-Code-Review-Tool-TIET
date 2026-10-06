"""The per-item memo: reuse the result for one item, usually a file, across scans (E04-22).

Owning epic: E04.

The stage cache (E04-21) is all or nothing: one edited file changes the digest of ``files`` and
every downstream stage recomputes the whole repository. The orchestrator cannot do better
generically because only a stage knows its items, so ``RunContext.memo`` gives a stage a small
service::

    table = ctx.memo.get_or_compute(
        "parse.symbols.v1",
        memo_key(f.sha256, f.language, GRAMMAR_VERSION),
        lambda: extract_symbols(f),
        SymbolTable,
    )

It returns the stored result for the namespace and key, or calls ``compute``, stores the result
and returns it. Entries live under ``<state>/cache/items/<namespace>/<aa>/<key>.json`` with the
containment, mode (``0o600``) and in-directory ``.gitignore`` rules of the artefact store, and use
its envelope (``encode_artefact``): no executable deserialisation, and the never-persist guard
refuses the scan salt and vault material (I3).

Rules for stage authors:

1. The key must cover everything the computation reads: the content hash of the file, the language,
   the tool or grammar version and any setting that changes the result. The path is not part of
   the key unless the result contains it; prefer path-free results and attach the path afterwards,
   so that renamed or duplicated files share entries.
2. Bump the version segment of the namespace (``parse.symbols.v1``) when the computation changes.
3. ``compute`` is deterministic and has no side effects.
4. Results are Pydantic models, lists of one model class, or JSON values, like artefacts.
   Transient objects cannot be memoised.

A wrong key can hide a finding after a code change, so the rules matter more than the mechanism.

An entry that cannot be read or decoded (truncated, corrupt, not valid for the requested model, or
holding another type) counts as a miss and an error and is overwritten. A failed write never fails
the stage: the computed value is returned and the failure is counted. Two threads that compute the
same missing item both write the same bytes, and the atomic replace makes that harmless, so there
is no per-key lock. Salt-dependent stages get a separate key space (``salt_fp`` folded into the
key, I5); the salt itself is in no path and no entry.
"""

import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from pydantic import BaseModel, JsonValue

from codekavach.core.log import get_logger
from codekavach.core.store.admin import touch
from codekavach.core.store.base import (
    ArtefactCorruptError,
    ArtefactError,
    ArtefactTypeError,
    EncodedArtefact,
    decode_json,
    decode_list,
    decode_model,
    encode_artefact,
)
from codekavach.core.store.layout import StateLayout, atomic_write_bytes

SEPARATOR: Final = "\x1f"
NAMESPACE_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
KEY_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
WRITE_ATTEMPTS: Final = 3
RETRY_SECONDS: Final = 0.002
_log = get_logger("codekavach.pipeline.memo")


class _Absent:
    """Marks a lookup that found nothing usable."""


_ABSENT: Final = _Absent()


def memo_key(*parts: str) -> str:
    """SHA-256 (hex) of ``parts`` joined with the unit separator (U+001F).

    A part may not contain the separator: with it, the parts ``("a<US>b", "c")`` and
    ``("a", "b<US>c")`` would give one key, and one stage's entry could answer another's.

    Raises:
        ValueError: there is no part, or a part contains the separator.
        TypeError: a part is not a string.
    """
    if not parts:
        raise ValueError("a memo key needs at least one part")
    for part in parts:
        if not isinstance(part, str):
            raise TypeError(f"a memo key part must be a string, not {type(part).__name__}")
        if SEPARATOR in part:
            raise ValueError("a memo key part may not contain the unit separator")
    return hashlib.sha256(SEPARATOR.join(parts).encode("utf-8")).hexdigest()


def check_arguments(namespace: str, item_key: str) -> None:
    """Refuse a namespace or item key of the wrong form, whichever memo is in use.

    Raises:
        ValueError: ``namespace`` is not ``[a-z][a-z0-9_.-]{0,63}`` or ``item_key`` is not 64
            lower-case hexadecimal characters; the values are not echoed.
    """
    if NAMESPACE_PATTERN.fullmatch(namespace) is None or ".." in namespace:
        raise ValueError("invalid memo namespace")
    if KEY_PATTERN.fullmatch(item_key) is None:
        raise ValueError("invalid memo item key: expected 64 lower-case hexadecimal characters")


@dataclass(frozen=True, slots=True)
class MemoStats:
    """Counters of one memo; ``errors`` entries are also counted as misses or write failures."""

    hits: int = 0
    misses: int = 0
    errors: int = 0

    def __add__(self, other: "MemoStats") -> "MemoStats":
        return MemoStats(
            self.hits + other.hits, self.misses + other.misses, self.errors + other.errors
        )


class ItemMemo(Protocol):
    """What a stage sees as ``ctx.memo``."""

    def get_or_compute[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], M], model: type[M]
    ) -> M:
        """The stored model for the namespace and key, or ``compute()`` stored and returned."""

    def get_or_compute_list[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], Sequence[M]], item: type[M]
    ) -> list[M]:
        """The same for a list of one model class."""

    def get_or_compute_json(
        self, namespace: str, item_key: str, compute: Callable[[], JsonValue]
    ) -> JsonValue:
        """The same for a JSON value."""

    def stats(self) -> MemoStats:
        """Hits, misses and errors so far."""


class NullMemo:
    """A memo that always computes and never touches the disk.

    Stages get it with ``--no-cache``, in unit tests and whenever no state directory exists. The
    arguments are still checked, so a bad namespace or key fails with the cache switched off too.
    """

    def get_or_compute[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], M], model: type[M]
    ) -> M:
        """Call ``compute`` after checking the arguments."""
        check_arguments(namespace, item_key)
        return compute()

    def get_or_compute_list[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], Sequence[M]], item: type[M]
    ) -> list[M]:
        """Call ``compute`` after checking the arguments."""
        check_arguments(namespace, item_key)
        return list(compute())

    def get_or_compute_json(
        self, namespace: str, item_key: str, compute: Callable[[], JsonValue]
    ) -> JsonValue:
        """Call ``compute`` after checking the arguments."""
        check_arguments(namespace, item_key)
        return compute()

    def stats(self) -> MemoStats:
        """Always zero: nothing is looked up."""
        return MemoStats()


def _as_encoded(raw: bytes) -> EncodedArtefact:
    """The stored bytes as an ``EncodedArtefact``; the shape and tag come from the envelope."""
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ArtefactCorruptError("memo entry is not a valid envelope") from None
    if not isinstance(envelope, dict):
        raise ArtefactCorruptError("memo entry is not a valid envelope")
    shape, tag = envelope.get("shape"), envelope.get("type")
    if shape not in ("model", "list", "json") or not isinstance(tag, str):
        raise ArtefactCorruptError("memo entry has an unknown shape")
    return EncodedArtefact(shape, tag, raw, hashlib.sha256(raw).hexdigest())


class DiskItemMemo:
    """Memo entries under ``<state>/cache/items``, written atomically."""

    def __init__(self, layout: StateLayout, *, salt_fp: str | None = None) -> None:
        self._layout = layout
        self._salt_fp = salt_fp
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._errors = 0

    def get_or_compute[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], M], model: type[M]
    ) -> M:
        """The stored model, or the computed one stored for next time."""

        def check(value: M) -> None:
            if not isinstance(value, model):
                raise ArtefactTypeError(
                    f"compute returned {type(value).__name__}, expected {model.__name__}"
                )

        return self._run(
            namespace,
            item_key,
            compute,
            lambda encoded: decode_model("memo", encoded, model),
            check,
        )

    def get_or_compute_list[M: BaseModel](
        self, namespace: str, item_key: str, compute: Callable[[], Sequence[M]], item: type[M]
    ) -> list[M]:
        """The stored list of ``item`` models, or the computed one stored for next time."""

        def check(values: Sequence[M]) -> None:
            if any(not isinstance(value, item) for value in values):
                raise ArtefactTypeError(
                    f"compute returned a list with items other than {item.__name__}"
                )

        result = self._run(
            namespace,
            item_key,
            lambda: list(compute()),
            lambda encoded: decode_list("memo", encoded, item),
            check,
        )
        return list(result)

    def get_or_compute_json(
        self, namespace: str, item_key: str, compute: Callable[[], JsonValue]
    ) -> JsonValue:
        """The stored JSON value, or the computed one stored for next time."""

        def decode(encoded: EncodedArtefact) -> JsonValue:
            # An empty list is stored with the "list" shape and no type tag; it is still JSON.
            if encoded.shape != "json" and not (encoded.shape == "list" and not encoded.type_tag):
                raise ArtefactTypeError(f"memo entry is a {encoded.shape}, not a JSON value")
            return decode_json("memo", encoded)

        return self._run(namespace, item_key, compute, decode, lambda value: None)

    def stats(self) -> MemoStats:
        """A snapshot of the counters."""
        with self._lock:
            return MemoStats(self._hits, self._misses, self._errors)

    # --- one lookup ----------------------------------------------------------------------------

    def _run[T](
        self,
        namespace: str,
        item_key: str,
        compute: Callable[[], T],
        decode: Callable[[EncodedArtefact], T],
        check: Callable[[T], None],
    ) -> T:
        check_arguments(namespace, item_key)
        effective = memo_key(item_key, self._salt_fp) if self._salt_fp else item_key
        path = self._layout.item_path(namespace, effective)
        cached = self._read(path, namespace, decode)
        if not isinstance(cached, _Absent):
            with self._lock:
                self._hits += 1
            touch(path)  # recency for pruning (E04-23); the modification time is the signal
            return cached
        with self._lock:
            self._misses += 1
        value = compute()
        check(value)
        encoded = encode_artefact(value)
        self._write(path, namespace, encoded.data)
        return value

    def _count_error(self) -> None:
        with self._lock:
            self._errors += 1

    def _read[T](
        self, path: Path, namespace: str, decode: Callable[[EncodedArtefact], T]
    ) -> T | _Absent:
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return _ABSENT
        except OSError as error:
            self._count_error()
            _log.warning(
                "memo_entry_unreadable", namespace=namespace, error_type=type(error).__name__
            )
            return _ABSENT
        try:
            return decode(_as_encoded(raw))
        except ArtefactError as error:
            self._count_error()
            _log.warning(
                "memo_entry_unusable", namespace=namespace, error_type=type(error).__name__
            )
            return _ABSENT

    def _write(self, path: Path, namespace: str, data: bytes) -> None:
        last: OSError | None = None
        for attempt in range(WRITE_ATTEMPTS):
            try:
                atomic_write_bytes(path, data)
                return
            except OSError as error:  # a concurrent reader can block the replace on Windows
                last = error
                time.sleep(RETRY_SECONDS * (attempt + 1))
        self._count_error()
        _log.warning(
            "memo_write_failed",
            namespace=namespace,
            error_type=type(last).__name__ if last else "OSError",
        )
