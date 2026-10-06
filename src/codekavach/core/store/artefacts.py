"""The content-addressed on-disk artefact store under the state directory.

Owning epic: E04.

Blobs (``cache/blobs/<aa>/<sha256>``) hold the canonical envelope bytes of E04-04, so a client can
inspect what was cached with ``cat`` and ``jq``; identical content is stored once across keys and
scans. Each scan has its own bindings (``scans/<scan_id>/index/<key>.json``) from logical keys to
blobs, which is what resume re-enters (E04-28). Transient values stay in process memory.

Concurrency: one process writes a given ``scan_id`` (single-writer assumption); several processes
may read it. Two scans in one state directory are safe for blobs (content-addressed, atomic
replace, idempotent) and use different binding directories. Threads of one process may write
concurrently; updates of one key's binding are serialised by a per-key lock.

Every read recomputes the blob's SHA-256 and compares it with the binding. That detects accidental
corruption and casual tampering; it is not an integrity control against an attacker who can
rewrite both blob and binding.
"""

import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any, Self

from pydantic import JsonValue

from codekavach.core.log import get_logger
from codekavach.core.pipeline.keys import is_valid_key
from codekavach.core.store.admin import touch
from codekavach.core.store.base import (
    ArtefactCorruptError,
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
from codekavach.core.store.layout import StateLayout, atomic_write_bytes
from codekavach.core.store.memory import check_key, check_part, multi_key, single_key

BINDING_VERSION = 1
LARGE_ARTEFACT_BYTES = 64 * 1024 * 1024
_SCAN_ID = re.compile(r"^scan_[0-9A-HJKMNP-TV-Z]{26}$")
_log = get_logger(__name__)


def list_scan_ids(layout: StateLayout) -> list[str]:
    """The scan ids with a record directory, oldest first (ULIDs sort by time)."""
    if not layout.scans_dir.is_dir():
        return []
    return sorted(
        path.name
        for path in layout.scans_dir.iterdir()
        if path.is_dir() and not path.is_symlink() and _SCAN_ID.match(path.name)
    )


class OnDiskArtefactStore:
    """An ``ArtefactStore`` whose persisted values survive the process."""

    def __init__(self, layout: StateLayout, scan_id: str) -> None:
        layout.scan_dir(scan_id)  # validates the scan id
        self._layout = layout
        self._scan_id = scan_id
        self._lock = threading.Lock()
        self._key_locks: dict[str, threading.Lock] = {}
        self._transient: dict[str, object] = {}
        self._ensured = False

    @classmethod
    def open_existing(cls, layout: StateLayout, scan_id: str) -> Self:
        """A store over the records of an earlier scan, for consumers in another process."""
        if not layout.scan_dir(scan_id).is_dir():
            raise ArtefactMissingError(f"no records for scan {scan_id!r}")
        return cls(layout, scan_id)

    def _ensure_root(self) -> None:
        """Create the state directory (0o700, self-ignoring) before the first write."""
        with self._lock:
            if not self._ensured:
                self._layout.ensure()
                self._ensured = True

    def _key_lock(self, key: str) -> threading.Lock:
        with self._lock:
            return self._key_locks.setdefault(key, threading.Lock())

    # Blobs

    def _write_blob(self, key: str, encoded: EncodedArtefact) -> None:
        if len(encoded.data) > LARGE_ARTEFACT_BYTES:
            _log.warning("artefact_large", key=key, size=len(encoded.data))
        self._ensure_root()
        path = self._layout.blob_path(encoded.digest)
        with self._key_lock(f"blob:{encoded.digest}"):
            if path.is_file() and path.stat().st_size == len(encoded.data):
                return
            try:
                atomic_write_bytes(path, encoded.data)
            except OSError:
                # Another process stored the same content first (Windows refuses to replace an
                # open file); identical bytes under the same digest are what we wanted.
                if not (path.is_file() and path.stat().st_size == len(encoded.data)):
                    raise

    def _blob_size(self, key: str, digest: str) -> int:
        path = self._layout.blob_path(digest)
        if not path.is_file():
            raise ArtefactMissingError(f"artefact {key!r} points to a missing blob")
        return path.stat().st_size

    def _read_blob(self, key: str, digest: str) -> EncodedArtefact:
        path = self._layout.blob_path(digest)
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            raise ArtefactMissingError(f"artefact {key!r} points to a missing blob") from None
        if hashlib.sha256(data).hexdigest() != digest:
            raise ArtefactCorruptError(f"artefact {key!r} does not match its digest")
        try:
            envelope = json.loads(data)
            shape, tag = envelope["shape"], envelope["type"]
        except (ValueError, KeyError, TypeError):
            raise ArtefactCorruptError(f"artefact {key!r} is not a valid envelope") from None
        return EncodedArtefact(shape, tag, data, digest)

    # Bindings

    def _binding_path(self, key: str) -> Path:
        return self._layout.index_path(self._scan_id, key)

    def _read_binding(self, key: str) -> dict[str, Any] | None:
        path = self._binding_path(key)
        try:
            binding = json.loads(path.read_bytes())
        except FileNotFoundError:
            return None
        except ValueError:
            raise ArtefactCorruptError(f"binding of artefact {key!r} is not valid JSON") from None
        if not isinstance(binding, dict) or binding.get("v") != BINDING_VERSION:
            raise ArtefactCorruptError(f"binding of artefact {key!r} has an unknown version")
        return binding

    def _write_binding(self, key: str, binding: dict[str, Any]) -> None:
        self._ensure_root()
        text = json.dumps(binding, sort_keys=True, separators=(",", ":"))
        atomic_write_bytes(self._binding_path(key), text.encode("utf-8"))

    def _single_binding(self, key: str, encoded: EncodedArtefact) -> dict[str, Any]:
        return {
            "v": BINDING_VERSION,
            "key": key,
            "digest": encoded.digest,
            "size": len(encoded.data),
            "shape": encoded.shape,
            "type": encoded.type_tag,
        }

    # Protocol

    def put(self, key: str, value: object, *, persist: bool = True) -> ArtefactRef:
        """Store ``value``; with ``persist=False`` keep the object in memory only."""
        single_key(key)
        if not persist:
            check_never_persist(value)
            with self._key_lock(key):
                self._binding_path(key).unlink(missing_ok=True)
                with self._lock:
                    self._transient[key] = value
            return ArtefactRef(key=key, digest=None, size=0)
        encoded = encode_artefact(value)
        self._write_blob(key, encoded)
        with self._key_lock(key):
            self._write_binding(key, self._single_binding(key, encoded))
            with self._lock:
                self._transient.pop(key, None)
        return ArtefactRef(key=key, digest=encoded.digest, size=len(encoded.data))

    def put_part(self, key: str, part: str, value: object) -> ArtefactRef:
        """Store one part of a multi-provider key."""
        multi_key(key)
        check_part(part)
        encoded = encode_artefact(value)
        self._write_blob(key, encoded)
        with self._key_lock(key):
            binding = self._read_binding(key) or {"v": BINDING_VERSION, "key": key, "parts": {}}
            binding["parts"][part] = {"digest": encoded.digest, "size": len(encoded.data)}
            self._write_binding(key, binding)
        return self._multi_ref(key, binding)

    def _multi_ref(self, key: str, binding: dict[str, Any]) -> ArtefactRef:
        parts = tuple(sorted((name, entry["digest"]) for name, entry in binding["parts"].items()))
        size = sum(int(entry["size"]) for entry in binding["parts"].values())
        return ArtefactRef(key=key, digest=parts_digest(parts), size=size, parts=parts)

    def _encoded(self, key: str) -> EncodedArtefact:
        check_key(key)
        with self._lock:
            if key in self._transient:
                raise ArtefactTypeError(f"artefact {key!r} is transient; use get_object")
        binding = self._read_binding(key)
        if binding is None:
            raise ArtefactMissingError(f"no artefact {key!r}")
        if "digest" not in binding:
            raise ArtefactTypeError(f"artefact {key!r} is multi-provider; use get_parts")
        return self._read_blob(key, str(binding["digest"]))

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
        if self._binding_path(key).exists():
            raise ArtefactTypeError(f"artefact {key!r} is persisted; use a typed getter")
        raise ArtefactMissingError(f"no artefact {key!r}")

    def get_parts(self, key: str, item: type[M]) -> dict[str, list[M]]:
        """Every part of ``key``, ordered by part name."""
        multi_key(key)
        binding = self._read_binding(key)
        if binding is None or not binding.get("parts"):
            raise ArtefactMissingError(f"no artefact {key!r}")
        result: dict[str, list[M]] = {}
        for name in sorted(binding["parts"]):
            label = f"{key}/{name}"
            encoded = self._read_blob(label, str(binding["parts"][name]["digest"]))
            if encoded.shape == "model":
                result[name] = [decode_model(label, encoded, item)]
            else:
                result[name] = decode_list(label, encoded, item)
        return result

    def has(self, key: str) -> bool:
        """True when ``key`` holds a value or at least one part."""
        check_key(key)
        with self._lock:
            if key in self._transient:
                return True
        binding = self._read_binding(key)
        return binding is not None and ("digest" in binding or bool(binding.get("parts")))

    def ref(self, key: str) -> ArtefactRef | None:
        """The reference of ``key``, or ``None`` when it holds nothing."""
        check_key(key)
        with self._lock:
            if key in self._transient:
                return ArtefactRef(key=key, digest=None, size=0)
        binding = self._read_binding(key)
        if binding is None:
            return None
        if "digest" in binding:
            return ArtefactRef(key=key, digest=binding["digest"], size=int(binding["size"]))
        if not binding.get("parts"):
            return None
        return self._multi_ref(key, binding)

    def bind_part(self, key: str, part: str, digest: str) -> None:
        """Point one part of ``key`` at an existing blob; the other parts are kept."""
        multi_key(key)
        check_part(part)
        size = self._blob_size(key, digest)
        touch(self._layout.blob_path(digest))  # a reused blob is recent for pruning (E04-23)
        with self._key_lock(key):
            binding = self._read_binding(key) or {"v": BINDING_VERSION, "key": key, "parts": {}}
            binding["parts"][part] = {"digest": digest, "size": size}
            self._write_binding(key, binding)

    def bind(self, key: str, ref: ArtefactRef) -> None:
        """Point ``key`` at blobs that already exist, without rewriting them."""
        check_key(key)
        if ref.parts:
            multi_key(key)
            parts = {}
            for part, digest in ref.parts:
                check_part(part)
                parts[part] = {"digest": digest, "size": self._blob_size(key, digest)}
                touch(self._layout.blob_path(digest))
            with self._key_lock(key):
                self._write_binding(key, {"v": BINDING_VERSION, "key": key, "parts": parts})
            return
        single_key(key)
        if ref.digest is None:
            raise ArtefactMissingError(f"no stored content for artefact {key!r}")
        self._blob_size(key, ref.digest)
        touch(self._layout.blob_path(ref.digest))
        encoded = self._read_blob(key, ref.digest)
        with self._key_lock(key):
            self._write_binding(key, self._single_binding(key, encoded))
            with self._lock:
                self._transient.pop(key, None)

    def discard(self, key: str, *, part: str | None = None) -> None:
        """Remove ``key`` or one part of it; blobs are kept (E04-23 collects garbage)."""
        check_key(key)
        with self._key_lock(key):
            if part is None:
                with self._lock:
                    self._transient.pop(key, None)
                self._binding_path(key).unlink(missing_ok=True)
                return
            check_part(part)
            binding = self._read_binding(key)
            if binding is None or part not in binding.get("parts", {}):
                return
            del binding["parts"][part]
            if binding["parts"]:
                self._write_binding(key, binding)
            else:
                self._binding_path(key).unlink(missing_ok=True)

    def keys(self) -> tuple[str, ...]:
        """Keys that hold a value, sorted."""
        found: set[str] = set()
        index = self._layout.index_dir(self._scan_id)
        if index.is_dir():
            for path in index.glob("*.json"):
                key = path.name.removesuffix(".json")
                if is_valid_key(key) and self.has(key):
                    found.add(key)
        with self._lock:
            found.update(self._transient)
        return tuple(sorted(found))
