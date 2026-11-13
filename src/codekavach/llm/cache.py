"""LLM cache: answers to sanitised payloads, keyed by what determines the answer (E22-03).

Owning epic: E22 to E24. Normative layout: docs/ARCHITECTURE.md section 3.

A second scan of unchanged code with the same scan salt produces the same payloads (I5), so the
same question would be asked again. The cache answers it from disk instead: no egress, no ledger
entry, no tokens. The key is SHA-256 over the provider kind, the endpoint host, the model, the
task, the prompt version and hash, the payload hash and the sample index, so changing the
prompt, the model or the sample is a miss.

**What is stored** is the provider's response body for a 2xx answer that parsed as a verdict: text
in pseudonym space, the same class of data as the ledger's completed entries and the replay
cassettes. It lives in the scan state directory (``<state>/llm-cache``), next to the vault whose
salt produced the pseudonyms, with owner-only permissions. A failed, refused or unparseable
answer is never cached, and neither is one the output defence rejects: ``ManagedSession`` holds an
answer back until the reviewer accepts it.
"""

import contextlib
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

CACHE_DIR: Final = "llm-cache"
_FILE_MODE: Final = 0o600
_DIR_MODE: Final = 0o700
_VERSION: Final = 1


@dataclass(frozen=True, slots=True)
class CacheKey:
    """The inputs that determine an answer."""

    kind: str
    host: str
    model: str
    task: str
    prompt_version: str
    prompt_hash: str
    payload_hash: str
    sample: int = 0

    @property
    def digest(self) -> str:
        """The file name of the entry."""
        material = json.dumps(
            [
                _VERSION,
                self.kind,
                self.host,
                self.model,
                self.task,
                self.prompt_version,
                self.prompt_hash,
                self.payload_hash,
                self.sample,
            ],
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CachedResponse:
    """A stored answer."""

    status: int
    body: bytes


class ResponseCache:
    """Answers on disk below ``directory``, one JSON file per key."""

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self.hits = 0
        self.misses = 0

    def _path(self, key: CacheKey) -> Path:
        digest = key.digest
        return self._dir / digest[:2] / f"{digest}.json"

    def get(self, key: CacheKey) -> CachedResponse | None:
        """The stored answer for ``key``, or ``None``; an unreadable entry is a miss."""
        path = self._path(key)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            found = CachedResponse(int(document["status"]), document["body"].encode("utf-8"))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            self.misses += 1
            return None
        self.hits += 1
        return found

    def put(self, key: CacheKey, status: int, body: bytes) -> None:
        """Store an answer; a failure to write is ignored (the cache is an optimisation)."""
        path = self._path(key)
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return
        document = json.dumps({"status": status, "body": text}, separators=(",", ":"))
        with contextlib.suppress(OSError):
            path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
            temporary = path.with_suffix(".tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(document)
            temporary.replace(path)
