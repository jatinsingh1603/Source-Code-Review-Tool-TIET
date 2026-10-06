"""The derivation-keyed stage cache: reuse a stage's outputs when its inputs are unchanged (E04-21).

Owning epic: E04.

Before a cacheable stage runs, the orchestrator computes its stage key (ADR-0007 D9):
``sha256`` over canonical JSON of the prefix ``ck-stage-v1``, the stage name, version and origin
(distribution and version), the settings fingerprint of its configuration sections (E03-39), the
salt fingerprint when the stage is salt dependent, and the digest of every declared input. On a
hit the recorded outputs are bound into the current scan and the stage is not called; on a miss
it runs and a record is written. A corrupt record, or one whose blobs are gone, is a miss.

A transient input (a parse tree) has no digest; the key of the stage that produced it stands in
(``derived:<producer key>:<key>``), because the object is a pure function of the producer's
inputs. When the producer has no key, the consumer is not cacheable in that run.

Soundness conditions for a cacheable stage (a stale ``candidates`` artefact would hide findings):

1. it reads client data only through its declared artefacts and the files listed in ``files``,
   whose hashes are inside that artefact (the scoped store of E04-17 enforces the first half);
2. its ``version`` is bumped whenever its logic changes (``origin`` also invalidates entries when
   a plugin is upgraded without a bump);
3. it does not depend on wall-clock time, randomness or environment variables.

Only PARSE, ANALYSE, AGGREGATE and RATE stages are cacheable by default (E04-02). Never cached:
INGEST (the root of change detection), PRIVACY, LLM and RESTORE (vault state, and every LLM
request must produce a ledger entry), REPORT and SYNC (side effects), and any stage with
transient outputs. Records hold digests and sizes only; the salt itself is in no key or record.
"""

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codekavach.config import Settings
from codekavach.config.snapshot import settings_fingerprint
from codekavach.core.log import get_logger
from codekavach.core.pipeline.stage import StageInfo
from codekavach.core.store.base import ArtefactStore, parts_digest
from codekavach.core.store.layout import StateLayout, atomic_write_bytes

STAGE_KEY_PREFIX = "ck-stage-v1"
RECORD_VERSION = 1
_log = get_logger("codekavach.pipeline.cache")


def compute_stage_key(
    info: StageInfo,
    *,
    config_fp: str,
    salt_fp: str | None,
    input_digests: Mapping[str, str | None],
) -> str:
    """The stage key: SHA-256 (hex) of canonical JSON of the key material."""
    material = {
        "v": STAGE_KEY_PREFIX,
        "stage": info.name,
        "version": info.version,
        "origin": info.origin or "",
        "config": config_fp,
        "salt": salt_fp,
        "inputs": [[key, input_digests[key]] for key in sorted(input_digests)],
    }
    text = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def input_digests(
    info: StageInfo,
    store: ArtefactStore,
    *,
    transient_producers: Mapping[str, str],
    stage_keys: Mapping[str, str],
) -> dict[str, str | None] | None:
    """Digests of every declared input, or ``None`` when one cannot be known.

    ``transient_producers`` maps a transient key to the stage that provides it, and
    ``stage_keys`` holds the keys computed so far in this run.
    """
    digests: dict[str, str | None] = {}
    for key in sorted(info.requires | info.optional_requires):
        producer = transient_producers.get(key)
        if producer is not None:
            producer_key = stage_keys.get(producer)
            if producer_key is None:
                return None
            digests[key] = f"derived:{producer_key}:{key}"
            continue
        ref = store.ref(key)
        if ref is None:
            digests[key] = None
        elif ref.parts:
            digests[key] = parts_digest(ref.parts)
        elif ref.digest is None:
            return None  # a transient value without a declared producer
        else:
            digests[key] = ref.digest
    return digests


@dataclass
class ConfigFingerprints:
    """Settings fingerprints per distinct ``config_sections`` value, computed once per run."""

    settings: Settings
    fingerprint: Callable[..., str] = settings_fingerprint
    _memo: dict[tuple[str, ...] | None, str] = field(default_factory=dict)

    def of(self, sections: tuple[str, ...] | None) -> str:
        """The fingerprint of ``sections`` (the default sections when ``None``)."""
        if sections not in self._memo:
            if sections is None:
                self._memo[sections] = self.fingerprint(self.settings)
            else:
                self._memo[sections] = self.fingerprint(self.settings, sections=sections)
        return self._memo[sections]


@dataclass(frozen=True, slots=True)
class StageCacheRecord:
    """What a successful cacheable stage produced: output digests, sizes and parts."""

    stage: str
    stage_key: str
    outputs: Mapping[str, Mapping[str, Any]]
    created_at: str
    codekavach_version: str
    duration_ms: int
    v: int = RECORD_VERSION

    def to_json(self) -> dict[str, Any]:
        """The on-disk form."""
        return {
            "v": self.v,
            "stage": self.stage,
            "stage_key": self.stage_key,
            "outputs": {key: dict(value) for key, value in sorted(self.outputs.items())},
            "created_at": self.created_at,
            "codekavach_version": self.codekavach_version,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "StageCacheRecord":
        """Parse the on-disk form.

        Raises:
            ValueError: the record is not version 1 or is malformed.
        """
        if data.get("v") != RECORD_VERSION:
            raise ValueError("unsupported stage cache record version")
        outputs = data["outputs"]
        if not isinstance(outputs, dict):
            raise ValueError("outputs must be an object")
        return cls(
            stage=str(data["stage"]),
            stage_key=str(data["stage_key"]),
            outputs={str(key): dict(value) for key, value in outputs.items()},
            created_at=str(data["created_at"]),
            codekavach_version=str(data["codekavach_version"]),
            duration_ms=int(data["duration_ms"]),
        )


class StageCache:
    """Stage cache records under ``<state>/cache/stages``, written atomically."""

    def __init__(self, layout: StateLayout) -> None:
        self._layout = layout

    @property
    def layout(self) -> StateLayout:
        """The state layout the records live in; the item memo (E04-22) uses the same one."""
        return self._layout

    def _path(self, stage_key: str) -> Path:
        return self._layout.stage_record_path(stage_key)

    def lookup(self, stage_key: str) -> StageCacheRecord | None:
        """The record for ``stage_key``; a missing record is ``None``, a corrupt one too."""
        path = self._path(stage_key)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            _log.warning("stage_cache_unreadable", stage_key=stage_key[:12])
            return None
        try:
            record = StageCacheRecord.from_json(json.loads(raw))
        except (ValueError, KeyError, TypeError):
            _log.warning("stage_cache_corrupt", stage_key=stage_key[:12])
            self.invalidate(stage_key)
            return None
        if record.stage_key != stage_key:
            _log.warning("stage_cache_mismatch", stage=record.stage)
            self.invalidate(stage_key)
            return None
        return record

    def store(self, record: StageCacheRecord) -> None:
        """Write ``record`` atomically (mode 0o600)."""
        text = json.dumps(record.to_json(), sort_keys=True, separators=(",", ":"))
        atomic_write_bytes(self._path(record.stage_key), text.encode("utf-8"))

    def invalidate(self, stage_key: str) -> None:
        """Remove the record for ``stage_key``; idempotent."""
        self._path(stage_key).unlink(missing_ok=True)
