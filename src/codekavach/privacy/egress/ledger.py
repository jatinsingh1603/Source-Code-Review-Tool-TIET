"""Egress ledger: the hash-chained, encrypted record of every payload that left or was blocked.

Owning epic: E12 (issue E12-03). Normative layout: docs/ARCHITECTURE.md section 3.

On disk, below the state directory (``StateLayout``)::

    ledger/header.json                  format, ledger id, key source, wrapped data key
    ledger/chain.ndjson                 the authority: one sealed EgressRecord per line
    ledger/index.sqlite3                a lookup index, rebuilt from the chain when lost or stale
    ledger/payloads/<aa>/<hash>         one body per payload hash (AES-256-GCM when encrypted)
    ledger/payloads/<aa>/<hash>.pruned  tombstone left when a body is pruned by age
    ledger/.lock                        file lock serialising appends across threads and processes

Verification always reads ``chain.ndjson`` and the payload bodies; the index is never trusted for a
verdict. Directories are created 0o700 and files 0o600 (POSIX), through the helpers of E04-02.

**What the chain proves, and what it does not.** Each entry's hash covers the entry and the hash of
its predecessor, so a modification, insertion, deletion, reordering or truncation changes what a
walk reads at a specific ``seq``. The chain is tamper-*evident*. It is not tamper-*proof*: a file
truncated and rewritten from scratch by someone who can recompute every hash is not detected,
because nothing outside this directory anchors the chain. External anchoring is future work.

**Crash safety.** An append writes the payload body first (atomic rename after fsync), then the
chain line, fsyncs it, and only then returns. A crash before the chain line leaves an orphaned
payload, which ``verify_payloads`` lists and which does not affect the chain. A chain line whose
payload is missing is a hard failure. A partial last line makes the writer refuse to append: it is
not repaired silently, because a silent repair would erase the evidence of a truncation.

**Payloads.** A payload is stored once per distinct hash; the index keeps a reference count of the
records that name it. Pruning removes a body only when no record newer than the cut-off names it,
and leaves a tombstone, so a pruned payload reads as ``payload_pruned`` and not as corruption.
Chain entries are never deleted.

**Keys.** The payloads are sealed under a random data key, which is wrapped by the master key from
``codekavach.privacy.vault.keys`` (the same key sources as the vault, one key-management story).
The header stores only the wrapped data key. ``privacy.egress.encrypt_at_rest`` is passed as
``encrypt_at_rest``; when it is false the bodies are readable on disk and that is the operator's
choice.

**Logging.** Nothing in this module logs or puts into an exception message any payload byte, any
payload text or any original value; errors name sequence numbers, reason codes and hashes only.
"""

import contextlib
import hashlib
import importlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from pydantic import SecretStr, ValidationError

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.egress import HEX64_PATTERN, EgressRecord, TokenCounts
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.errors import ModelError
from codekavach.core.models.ids import CandidateId, ScanId
from codekavach.core.models.summary import EgressTotals
from codekavach.core.models.text import SanitisedText
from codekavach.core.store.layout import FILE_MODE, StateLayout, atomic_write_bytes, secure_mkdir
from codekavach.privacy.vault.crypto import (
    NONCE_BYTES,
    RecordCipher,
    new_data_key,
    unwrap_data_key,
    wrap_data_key,
)
from codekavach.privacy.vault.errors import VaultError
from codekavach.privacy.vault.keys import KeySource, ScryptParams, SecretBytes, resolve_master_key

__all__ = [
    "ChainReport",
    "EgressDraft",
    "LedgerError",
    "LedgerIntegrityError",
    "LedgerKeyError",
    "LedgerReader",
    "LedgerWriter",
    "PayloadIssue",
    "PayloadReport",
    "open_reader",
    "open_writer",
]

_LOG = get_logger("codekavach.privacy.egress.ledger")

LEDGER_DIR: Final = "ledger"
HEADER_FILE: Final = "header.json"
CHAIN_FILE: Final = "chain.ndjson"
INDEX_FILE: Final = "index.sqlite3"
LOCK_FILE: Final = ".lock"
PAYLOAD_DIR: Final = "payloads"
TOMBSTONE_SUFFIX: Final = ".pruned"
FORMAT_VERSION: Final = 1
LOCK_TIMEOUT_SECONDS: Final = 30.0
LOCK_POLL_SECONDS: Final = 0.005
TAIL_CHUNK_BYTES: Final = 64 * 1024
_HEX64 = re.compile(HEX64_PATTERN)
_LEDGER_ID = re.compile(r"^[0-9a-f]{16}$")
_PAYLOAD_AAD_PREFIX: Final = b"ck-ledger-payload-v1\x00"
_TIMESTAMP_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.%f"
_INDEX_SCHEMA: Final = (
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, offset INTEGER NOT NULL, "
    "length INTEGER NOT NULL, scan_id TEXT NOT NULL, candidate_id TEXT, "
    "payload_hash TEXT NOT NULL, timestamp TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS records_payload ON records(payload_hash)",
    "CREATE INDEX IF NOT EXISTS records_candidate ON records(candidate_id)",
    "CREATE TABLE IF NOT EXISTS payloads "
    "(payload_hash TEXT PRIMARY KEY, refcount INTEGER NOT NULL)",
)

_IS_WINDOWS: Final = os.name == "nt"
_PROCESS_LOCKS: dict[str, threading.Lock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


class LedgerError(Exception):
    """The ledger cannot be used; the message names the cause and never a payload byte."""


class LedgerIntegrityError(LedgerError):
    """The ledger on disk is not a valid chain or payload store.

    The message names a sequence number or a reason code, never payload bytes.
    """


class LedgerKeyError(LedgerError):
    """The payload key is unavailable here or does not open this ledger."""


@dataclass(frozen=True, slots=True)
class EgressDraft:
    """The fields of one ledger entry before sealing.

    ``seq``, ``prev_hash`` and ``entry_hash`` are assigned by ``LedgerWriter.append``.
    """

    timestamp: datetime
    scan_id: str
    candidate_id: str | None
    provider: str
    model: str
    task: str | None
    level: PrivacyLevel
    payload_hash: str
    token_counts: TokenCounts
    outcome: EgressOutcome
    request_hash: str | None = None
    block_code: str | None = None
    ref_seq: int | None = None


@dataclass(frozen=True, slots=True)
class ChainReport:
    """The result of walking the chain.

    ``first_bad_seq`` and ``reason`` are set only when ``ok`` is false.
    """

    ok: bool
    entries: int
    first_bad_seq: int | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class PayloadIssue:
    """One record whose stored payload is missing, unreadable or does not match its hash."""

    seq: int
    payload_hash: str
    reason: str


@dataclass(frozen=True, slots=True)
class PayloadReport:
    """The result of checking every stored payload against the records that name it.

    ``orphans`` lists stored files that no chain entry names (for example after a crash between the
    payload write and the chain append). They are reported and do not make the report fail.
    """

    ok: bool
    checked: int
    issues: tuple[PayloadIssue, ...]
    pruned_seqs: tuple[int, ...]
    orphans: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Header:
    ledger_id: str
    encrypted: bool
    key_source: str
    kdf: dict[str, Any] | None
    wrapped: bytes | None

    @classmethod
    def from_json(cls, data: object) -> "_Header":
        try:
            if not isinstance(data, dict) or data.get("format_version") != FORMAT_VERSION:
                raise ValueError
            ledger_id = data["ledger_id"]
            encrypted = data["encrypted"]
            key_source = data["key_source"]
            kdf = data.get("kdf")
            wrapped_hex = data.get("wrapped_data_key")
            if not isinstance(ledger_id, str) or not _LEDGER_ID.match(ledger_id):
                raise ValueError
            if not isinstance(encrypted, bool) or not isinstance(key_source, str):
                raise ValueError
            wrapped = None if wrapped_hex is None else bytes.fromhex(str(wrapped_hex))
            return cls(ledger_id, encrypted, key_source, kdf, wrapped)
        except (KeyError, TypeError, ValueError):
            raise LedgerIntegrityError("the ledger header is invalid") from None

    def to_json(self) -> bytes:
        document = {
            "format_version": FORMAT_VERSION,
            "ledger_id": self.ledger_id,
            "encrypted": self.encrypted,
            "key_source": self.key_source,
            "kdf": self.kdf,
            "wrapped_data_key": None if self.wrapped is None else self.wrapped.hex(),
        }
        return json.dumps(document, sort_keys=True).encode("utf-8")


def _utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _stamp(moment: datetime) -> str:
    return _utc(moment).strftime(_TIMESTAMP_FORMAT)


def _check_hash(payload_hash: str) -> str:
    if not _HEX64.fullmatch(payload_hash):
        raise ValueError("a payload hash is 64 lower-case hexadecimal characters")
    return payload_hash


def _as_draft(value: EgressRecord | EgressDraft) -> EgressDraft:
    if isinstance(value, EgressDraft):
        return value
    return EgressDraft(
        timestamp=value.timestamp,
        scan_id=value.scan_id,
        candidate_id=value.candidate_id,
        provider=value.provider,
        model=value.model,
        task=value.task,
        level=value.level,
        payload_hash=value.payload_hash,
        token_counts=value.token_counts,
        outcome=value.outcome,
        request_hash=value.request_hash,
        block_code=value.block_code,
        ref_seq=value.ref_seq,
    )


def _entry_reason(error: ValidationError) -> str:
    messages = " ".join(str(item.get("msg", "")) for item in error.errors(include_input=False))
    if "entry_hash does not match" in messages:
        return "entry_hash_mismatch"
    if "genesis" in messages:
        return "genesis_mismatch"
    return "invalid_record"


def _link_reason(message: str) -> str:
    if "previous hash mismatch" in message:
        return "prev_hash_mismatch"
    if "timestamp regression" in message:
        return "timestamp_regression"
    if "bad genesis" in message:
        return "genesis_mismatch"
    return "link_invalid"


def _decode(raw: bytes) -> EgressRecord | None:
    try:
        return EgressRecord.model_validate_json(raw)
    except ValueError:
        return None


def _seal_payload(cipher: RecordCipher, ledger_id: str, data: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce + cipher.seal(nonce, _PAYLOAD_AAD_PREFIX + ledger_id.encode(), data)


def _open_payload(cipher: RecordCipher, ledger_id: str, blob: bytes) -> bytes:
    if len(blob) <= NONCE_BYTES:
        raise LedgerIntegrityError("a stored payload is too short to be valid")
    try:
        return cipher.open(
            blob[:NONCE_BYTES], _PAYLOAD_AAD_PREFIX + ledger_id.encode(), blob[NONCE_BYTES:]
        )
    except (ValueError, VaultError):
        raise LedgerIntegrityError("a stored payload cannot be authenticated") from None


def _key_bytes(key: SecretStr) -> SecretBytes:
    try:
        return SecretBytes(bytes.fromhex(key.get_secret_value()))
    except ValueError:
        raise LedgerKeyError("the supplied ledger key is not a valid key") from None


def _candidate(value: str | None) -> CandidateId | None:
    return None if value is None else CandidateId(value)


def _account(ledger_id: str) -> str:
    return f"ledger-{ledger_id}"


def _open_lock_file(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, FILE_MODE)


def _try_lock(descriptor: int) -> bool:
    if _IS_WINDOWS:
        msvcrt = importlib.import_module("msvcrt")
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    fcntl = importlib.import_module("fcntl")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(descriptor: int) -> None:
    if _IS_WINDOWS:
        msvcrt = importlib.import_module("msvcrt")
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    fcntl = importlib.import_module("fcntl")
    fcntl.flock(descriptor, fcntl.LOCK_UN)


class _FileLock:
    """Serialises appends: a process-wide lock per path, then an OS file lock that waits."""

    def __init__(self, path: Path) -> None:
        self._path = path
        key = os.path.abspath(path)  # noqa: PTH100 - a lexical key on purpose
        with _PROCESS_LOCKS_GUARD:
            self._thread_lock = _PROCESS_LOCKS.setdefault(key, threading.Lock())
        self._descriptor: int | None = None

    def __enter__(self) -> None:
        if not self._thread_lock.acquire(timeout=LOCK_TIMEOUT_SECONDS):
            raise LedgerError("the ledger is busy; try again")
        try:
            self._descriptor = _open_lock_file(self._path)
            deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
            while not _try_lock(self._descriptor):
                if time.monotonic() >= deadline:
                    raise LedgerError("the ledger is busy; try again")
                time.sleep(LOCK_POLL_SECONDS)
        except BaseException:
            self._release()
            raise

    def __exit__(self, *_exc: object) -> None:
        self._release()

    def _release(self) -> None:
        try:
            if self._descriptor is not None:
                with contextlib.suppress(OSError):
                    _unlock(self._descriptor)
                os.close(self._descriptor)
                self._descriptor = None
        finally:
            self._thread_lock.release()


class _Index:
    """A rebuildable SQLite lookup index over the chain file; never the source of a verdict."""

    def __init__(self, path: Path, chain: Path) -> None:
        self._path = path
        self._chain = chain

    def _connect(self) -> sqlite3.Connection:
        if not self._path.exists():
            descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, FILE_MODE)
            os.close(descriptor)
        return sqlite3.connect(self._path, timeout=LOCK_TIMEOUT_SECONDS, isolation_level=None)

    def discard(self) -> None:
        """Remove the index files; the next sync rebuilds them from the chain."""
        for path in (self._path, self._sidecar("-wal"), self._sidecar("-shm")):
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)

    def _sidecar(self, suffix: str) -> Path:
        return self._path.with_name(self._path.name + suffix)

    def sync(self) -> None:
        """Index every complete chain line not yet indexed; rebuild when the index is ahead."""
        try:
            self._sync_once()
        except sqlite3.Error:
            _LOG.warning("ledger_index_rebuilt")
            self.discard()
            try:
                self._sync_once()
            except sqlite3.Error:
                raise LedgerError("the ledger index is unavailable") from None

    def _sync_once(self) -> None:
        size = self._chain.stat().st_size if self._chain.exists() else 0
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for statement in _INDEX_SCHEMA:
                    connection.execute(statement)
                row = connection.execute("SELECT v FROM meta WHERE k = 'indexed_bytes'").fetchone()
                indexed = None if row is None else int(row[0])
                if indexed is None or indexed > size:
                    connection.execute("DELETE FROM records")
                    connection.execute("DELETE FROM payloads")
                    indexed = 0
                if indexed < size:
                    indexed = self._index_tail(connection, indexed)
                connection.execute(
                    "INSERT OR REPLACE INTO meta (k, v) VALUES ('indexed_bytes', ?)",
                    (str(indexed),),
                )
                connection.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

    def _index_tail(self, connection: sqlite3.Connection, start: int) -> int:
        offset = start
        with self._chain.open("rb") as handle:
            handle.seek(start)
            for raw in handle:
                if not raw.endswith(b"\n"):
                    break
                record = _decode(raw[:-1])
                if record is None:
                    break
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO records VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        record.seq,
                        offset,
                        len(raw),
                        record.scan_id,
                        record.candidate_id,
                        record.payload_hash,
                        _stamp(record.timestamp),
                    ),
                )
                if inserted.rowcount == 1:
                    connection.execute(
                        "INSERT INTO payloads (payload_hash, refcount) VALUES (?, 1) "
                        "ON CONFLICT(payload_hash) DO UPDATE SET refcount = refcount + 1",
                        (record.payload_hash,),
                    )
                offset += len(raw)
        return offset

    def read[T](self, query: Callable[[sqlite3.Connection], T]) -> T:
        """Run ``query`` on a fresh connection after bringing the index up to date.

        With no chain file the ledger is empty: the query runs on an empty in-memory schema, so
        reading an absent ledger creates nothing on disk.
        """
        if not self._chain.is_file():
            empty = sqlite3.connect(":memory:")
            try:
                for statement in _INDEX_SCHEMA:
                    empty.execute(statement)
                return query(empty)
            except sqlite3.Error:
                raise LedgerError("the ledger index is unavailable") from None
            finally:
                empty.close()
        self.sync()
        connection = self._connect()
        try:
            return query(connection)
        except sqlite3.Error:
            raise LedgerError("the ledger index is unavailable") from None
        finally:
            connection.close()


class LedgerReader:
    """Read access to the ledger of one state directory; decryption happens only on this path.

    ``records`` streams the chain file; ``payload_text``, ``records_for_payload`` and
    ``records_for_candidate`` use the index for lookup and then decrypt the payload when asked.
    An absent ledger reads as empty. ``key`` supplies the master key directly; otherwise the key
    source recorded in the header is consulted (keyring, passphrase, ephemeral in tests).
    """

    def __init__(
        self,
        layout: StateLayout,
        *,
        key: SecretStr | None = None,
        settings: Settings | None = None,
        prompt: Callable[[], str] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self._layout = layout
        self._dir = layout.contain(layout.root / LEDGER_DIR)
        self._chain = self._dir / CHAIN_FILE
        self._header_path = self._dir / HEADER_FILE
        self._payloads = self._dir / PAYLOAD_DIR
        self._index = _Index(self._dir / INDEX_FILE, self._chain)
        self._key = key
        self._settings = settings
        self._prompt = prompt
        self._env = env
        self._cipher: RecordCipher | None = None

    def __repr__(self) -> str:
        return "LedgerReader(<state directory>)"

    # --- header and keys ------------------------------------------------------------------

    def _load_header(self) -> _Header | None:
        if not self._header_path.is_file():
            return None
        try:
            data = json.loads(self._header_path.read_bytes())
        except ValueError:
            raise LedgerIntegrityError("the ledger header is invalid") from None
        return _Header.from_json(data)

    def _master_key(self, header: _Header) -> SecretBytes:
        if self._key is not None:
            return _key_bytes(self._key)
        if header.key_source == "caller":
            raise LedgerKeyError("this ledger was written with a supplied key; pass key=")
        try:
            source = KeySource(header.key_source)
            kdf = None if header.kdf is None else ScryptParams.from_json(header.kdf)
            return resolve_master_key(
                source,
                settings=self._settings,
                prompt=self._prompt,
                account=_account(header.ledger_id),
                kdf=kdf,
                env=self._env,
                create=False,
            )
        except (ValueError, VaultError) as error:
            raise LedgerKeyError(str(error) or "the ledger key is unavailable") from None

    def _unwrap(self, header: _Header) -> RecordCipher:
        if header.wrapped is None:
            raise LedgerIntegrityError("the ledger header holds no wrapped data key")
        master = self._master_key(header)
        try:
            data_key = unwrap_data_key(master.reveal(), header.wrapped)
        except VaultError:
            raise LedgerKeyError("the key does not open this ledger") from None
        return RecordCipher(data_key)

    def _cipher_for(self, header: _Header | None) -> RecordCipher | None:
        if header is None or not header.encrypted:
            return None
        if self._cipher is None:
            self._cipher = self._unwrap(header)
        return self._cipher

    # --- the chain ------------------------------------------------------------------------

    def _lines(self) -> Iterator[tuple[int, bytes, bool]]:
        """Each line of the chain file as (byte offset, line without its newline, complete)."""
        if not self._chain.is_file():
            return
        with self._chain.open("rb") as handle:
            offset = 0
            for raw in handle:
                complete = raw.endswith(b"\n")
                body = raw[:-1] if complete else raw
                yield offset, body, complete
                offset += len(raw)

    def verify_chain(self) -> ChainReport:
        """Walk every entry in ``seq`` order and stop at the first divergence (no payload text)."""
        prev: EgressRecord | None = None
        expected = 1
        walked = 0
        for _offset, raw, complete in self._lines():
            if not complete:
                return ChainReport(False, walked, expected, "truncated_line")
            try:
                document = json.loads(raw)
            except ValueError:
                return ChainReport(False, walked, expected, "malformed_line")
            seq = document.get("seq") if isinstance(document, dict) else None
            if type(seq) is not int or seq != expected:
                return ChainReport(False, walked, expected, "seq_gap")
            try:
                record = EgressRecord.model_validate_json(raw)
            except ValidationError as error:
                return ChainReport(False, walked, expected, _entry_reason(error))
            try:
                record.verify_link(prev)
            except ModelError as error:
                return ChainReport(False, walked, expected, _link_reason(str(error)))
            prev = record
            walked += 1
            expected += 1
        return ChainReport(True, walked, None, None)

    def records(self, scan_id: str | None = None) -> Iterator[EgressRecord]:
        """Records in ``seq`` order, of one scan or of all scans.

        Raises:
            LedgerIntegrityError: an entry cannot be read; ``verify_chain`` names its seq.
        """
        expected = 1
        for _offset, raw, complete in self._lines():
            record = _decode(raw) if complete else None
            if record is None:
                raise LedgerIntegrityError(f"entry {expected} cannot be read; run verify_chain")
            expected += 1
            if scan_id is None or record.scan_id == scan_id:
                yield record

    def totals(self, scan_id: str | None = None) -> EgressTotals:
        """Totals for the report's privacy attestation; the chain must be intact."""
        report = self.verify_chain()
        if not report.ok:
            raise LedgerIntegrityError(f"the chain is not intact at seq {report.first_bad_seq}")
        return EgressTotals.from_records(self.records(scan_id))

    def _read_span(self, offset: int, length: int, seq: int) -> EgressRecord:
        with self._chain.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(length)
        record = _decode(raw[:-1]) if raw.endswith(b"\n") else None
        if record is None or record.seq != seq:
            raise LedgerIntegrityError(f"the index disagrees with the chain at seq {seq}")
        return record

    def _records_matching(self, rows: list[tuple[int, int, int]]) -> tuple[EgressRecord, ...]:
        return tuple(self._read_span(offset, length, seq) for seq, offset, length in rows)

    def records_for_payload(self, payload_hash: str) -> tuple[EgressRecord, ...]:
        """Every record that names ``payload_hash``, in ``seq`` order."""
        _check_hash(payload_hash)
        rows = self._index.read(
            lambda conn: conn.execute(
                "SELECT seq, offset, length FROM records WHERE payload_hash = ? ORDER BY seq",
                (payload_hash,),
            ).fetchall()
        )
        return self._records_matching(rows)

    def records_for_candidate(self, candidate_id: str) -> tuple[EgressRecord, ...]:
        """Every attempt for one candidate, blocked and dry-run ones included, in ``seq`` order."""
        rows = self._index.read(
            lambda conn: conn.execute(
                "SELECT seq, offset, length FROM records WHERE candidate_id = ? ORDER BY seq",
                (candidate_id,),
            ).fetchall()
        )
        return self._records_matching(rows)

    # --- the payload store ----------------------------------------------------------------

    def _body_path(self, payload_hash: str) -> Path:
        return self._layout.contain(self._payloads / payload_hash[:2] / payload_hash)

    def _tombstone(self, payload_hash: str) -> Path:
        return self._layout.contain(
            self._payloads / payload_hash[:2] / (payload_hash + TOMBSTONE_SUFFIX)
        )

    def _read_body(self, payload_hash: str) -> bytes | None:
        """The decrypted body, or ``None`` when it is pruned or absent."""
        if self._tombstone(payload_hash).exists():
            return None
        path = self._body_path(payload_hash)
        if not path.is_file():
            return None
        blob = path.read_bytes()
        header = self._load_header()
        if header is None or not header.encrypted:
            return blob
        cipher = self._cipher_for(header)
        if cipher is None:  # pragma: no cover - an encrypted header always yields a cipher
            raise LedgerKeyError("the payload key is unavailable")
        return _open_payload(cipher, header.ledger_id, blob)

    def payload_text(self, payload_hash: str) -> SanitisedText | None:
        """The payload exactly as it was serialised, or ``None`` when it is not stored or pruned.

        This is the only decryption path. The bytes are not compared with ``payload_hash`` here:
        ``verify_payloads`` does that, so a mismatch is reported as such and not hidden.

        Raises:
            LedgerKeyError: the key does not open this ledger.
            LedgerIntegrityError: the stored bytes fail authentication or are not UTF-8.
        """
        _check_hash(payload_hash)
        known = self._index.read(
            lambda conn: conn.execute(
                "SELECT 1 FROM payloads WHERE payload_hash = ?", (payload_hash,)
            ).fetchone()
        )
        if known is None:
            return None
        data = self._read_body(payload_hash)
        if data is None:
            return None
        try:
            return SanitisedText(data.decode("utf-8"))
        except UnicodeDecodeError:
            raise LedgerIntegrityError("a stored payload is not valid UTF-8") from None

    def verify_payloads(self) -> PayloadReport:
        """Check every payload named by a chain entry against its hash; list orphans and prunes."""
        referencing: dict[str, list[int]] = {}
        issues: list[PayloadIssue] = []
        pruned: list[int] = []
        checked = 0
        expected = 1
        for _offset, raw, complete in self._lines():
            record = _decode(raw) if complete else None
            if record is None:
                # The entry names no payload that can be read; the chain check reports why.
                issues.append(PayloadIssue(expected, "", "entry_unreadable"))
                break
            referencing.setdefault(record.payload_hash, []).append(record.seq)
            expected += 1
        for payload_hash in sorted(referencing):
            seqs = referencing[payload_hash]
            if self._tombstone(payload_hash).exists():
                pruned.extend(seqs)
                continue
            if not self._body_path(payload_hash).is_file():
                issues.extend(PayloadIssue(seq, payload_hash, "payload_missing") for seq in seqs)
                continue
            try:
                data = self._read_body(payload_hash)
            except (LedgerError, OSError):
                issues.extend(PayloadIssue(seq, payload_hash, "payload_unreadable") for seq in seqs)
                continue
            if data is None or hashlib.sha256(data).hexdigest() != payload_hash:
                issues.extend(PayloadIssue(seq, payload_hash, "payload_mismatch") for seq in seqs)
                continue
            checked += 1
        return PayloadReport(
            ok=not issues,
            checked=checked,
            issues=tuple(issues),
            pruned_seqs=tuple(sorted(pruned)),
            orphans=self._orphans(set(referencing)),
        )

    def _orphans(self, referenced: set[str]) -> tuple[str, ...]:
        if not self._payloads.is_dir():
            return ()
        found: list[str] = []
        for directory in sorted(self._payloads.iterdir()):
            if not directory.is_dir():
                continue
            for entry in sorted(directory.iterdir()):
                name = entry.name
                if name.endswith(TOMBSTONE_SUFFIX):
                    continue
                if _HEX64.fullmatch(name) and name in referenced:
                    continue
                found.append(name)
        return tuple(found)


class LedgerWriter(LedgerReader):
    """Appends sealed entries and stores their payloads; every append holds the ledger lock."""

    def __init__(
        self,
        layout: StateLayout,
        *,
        key: SecretStr | None,
        encrypt_at_rest: bool,
        key_source: str,
        settings: Settings | None,
        prompt: Callable[[], str] | None,
        env: Mapping[str, str] | None,
    ) -> None:
        super().__init__(layout, key=key, settings=settings, prompt=prompt, env=env)
        self._encrypt = encrypt_at_rest
        self._header_value: _Header | None = None
        self._key_source = key_source
        self._lock_path = self._dir / LOCK_FILE
        secure_mkdir(self._dir)
        with _FileLock(self._lock_path):
            existing = self._load_header()
            if existing is None:
                self._header_value = self._create_header()
            elif existing.encrypted != encrypt_at_rest:
                raise LedgerError("this ledger's encryption setting differs from the config")
            else:
                self._header_value = existing

    def __repr__(self) -> str:
        return "LedgerWriter(<state directory>)"

    def _create_header(self) -> _Header:
        ledger_id = secrets.token_hex(8)
        if not self._encrypt:
            header = _Header(ledger_id, False, "none", None, None)
        else:
            kdf_record: dict[str, Any] | None = None
            if self._key is not None:
                master = _key_bytes(self._key)
                source = "caller"
            else:
                try:
                    chosen = KeySource(self._key_source)
                except ValueError:
                    raise LedgerKeyError("unknown ledger key source") from None
                kdf = ScryptParams.fresh() if chosen is KeySource.PASSPHRASE else None
                kdf_record = None if kdf is None else kdf.to_json()
                source = chosen.value
                try:
                    master = resolve_master_key(
                        chosen,
                        settings=self._settings,
                        prompt=self._prompt,
                        account=_account(ledger_id),
                        kdf=kdf,
                        env=self._env,
                        create=True,
                    )
                except VaultError as error:
                    raise LedgerKeyError(str(error) or "the ledger key is unavailable") from None
            data_key = new_data_key()
            wrapped = wrap_data_key(master.reveal(), data_key)
            self._cipher = RecordCipher(data_key)
            header = _Header(ledger_id, True, source, kdf_record, wrapped)
        atomic_write_bytes(self._header_path, header.to_json())
        return header

    def _current_header(self) -> _Header:
        if self._header_value is None:
            raise LedgerError("the ledger has no header")
        return self._header_value

    def _last_record(self) -> EgressRecord | None:
        if not self._chain.is_file() or self._chain.stat().st_size == 0:
            return None
        with self._chain.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            handle.seek(size - 1)
            if handle.read(1) != b"\n":
                raise LedgerIntegrityError("the chain ends in an incomplete line; not appending")
            end = size - 1
            line_start = 0
            window = TAIL_CHUNK_BYTES
            while True:
                start = max(0, end - window)
                handle.seek(start)
                chunk = handle.read(end - start)
                cut = chunk.rfind(b"\n")
                if cut != -1:
                    line_start = start + cut + 1
                    break
                if start == 0:
                    line_start = 0
                    break
                window *= 2
            handle.seek(line_start)
            raw = handle.read(end - line_start)
        record = _decode(raw)
        if record is None:
            raise LedgerIntegrityError("the last entry cannot be read; run verify_chain")
        return record

    def _write_body(self, header: _Header, payload_hash: str, data: bytes) -> None:
        path = self._body_path(payload_hash)
        tombstone = self._tombstone(payload_hash)
        if path.is_file() and not tombstone.exists():
            return  # content-addressed: an identical payload is already stored once
        cipher = self._cipher_for(header)
        blob = data if cipher is None else _seal_payload(cipher, header.ledger_id, data)
        atomic_write_bytes(path, blob)
        tombstone.unlink(missing_ok=True)

    def _write_line(self, record: EgressRecord) -> None:
        view = memoryview(record.model_dump_json().encode("utf-8") + b"\n")
        descriptor = os.open(
            self._chain,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0),
            FILE_MODE,
        )
        try:
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def append(
        self, record: EgressRecord | EgressDraft, payload: SanitisedText | None = None
    ) -> EgressRecord:
        """Seal the next entry, store its payload and append its line; returns the sealed record.

        ``payload`` must be given for a request that carries one. ``None`` is allowed only for an
        entry that refers to a payload already stored (for example a ``completed`` follow-up), and
        the payload hash must then be known to the ledger.

        Raises:
            TypeError: ``payload`` is not a ``SanitisedText``.
            ValueError: the payload does not hash to ``payload_hash``, or no stored payload
                matches it.
            LedgerIntegrityError: the chain cannot be extended safely; nothing was written.
        """
        draft = _as_draft(record)
        _check_hash(draft.payload_hash)
        data: bytes | None = None
        if payload is not None:
            if not isinstance(payload, SanitisedText):
                raise TypeError("a payload must be a SanitisedText")
            data = payload.expose().encode("utf-8")
            if hashlib.sha256(data).hexdigest() != draft.payload_hash:
                raise ValueError("the payload does not hash to its payload_hash")
        with _FileLock(self._lock_path):
            header = self._current_header()
            previous = self._last_record()  # from the chain file; the index is not on this path
            timestamp = _utc(draft.timestamp)
            if previous is not None and timestamp < previous.timestamp:
                timestamp = previous.timestamp  # clocks of two writers may disagree; never regress
            if data is not None:
                self._write_body(header, draft.payload_hash, data)
            elif (
                self._index.read(
                    lambda conn: conn.execute(
                        "SELECT 1 FROM payloads WHERE payload_hash = ?", (draft.payload_hash,)
                    ).fetchone()
                )
                is None
            ):
                raise ValueError("no stored payload matches this payload_hash")
            sealed = EgressRecord.seal(
                prev=previous,
                timestamp=timestamp,
                scan_id=ScanId(draft.scan_id),
                candidate_id=None
                if draft.candidate_id is None
                else CandidateId(draft.candidate_id),
                provider=draft.provider,
                model=draft.model,
                task=draft.task,
                level=draft.level,
                payload_hash=draft.payload_hash,
                token_counts=draft.token_counts,
                outcome=draft.outcome,
                request_hash=draft.request_hash,
                block_code=draft.block_code,
                ref_seq=draft.ref_seq,
            )
            self._write_line(sealed)  # the index catches up on its next use, from the chain
        _LOG.info("ledger_append", seq=sealed.seq, outcome=sealed.outcome.value)
        return sealed

    def prune(self, older_than: datetime) -> int:
        """Remove the bodies of payloads that no record newer than ``older_than`` names.

        Chain entries are never removed; a pruned payload leaves a tombstone and reads as
        ``payload_pruned``. Returns the number of bodies pruned.
        """
        cutoff = _stamp(older_than)
        with _FileLock(self._lock_path):
            self._index.sync()
            hashes = self._index.read(
                lambda conn: [
                    row[0]
                    for row in conn.execute(
                        "SELECT p.payload_hash FROM payloads p WHERE NOT EXISTS ("
                        "SELECT 1 FROM records r WHERE r.payload_hash = p.payload_hash "
                        "AND r.timestamp >= ?)",
                        (cutoff,),
                    )
                ]
            )
            pruned = 0
            for payload_hash in hashes:
                body = self._body_path(payload_hash)
                if not body.is_file():
                    continue  # a missing body is a verification finding, not a prune candidate
                atomic_write_bytes(self._tombstone(payload_hash), b"")
                body.unlink(missing_ok=True)
                pruned += 1
        _LOG.info("ledger_pruned", bodies=pruned)
        return pruned


def _layout_of(state_dir: Path | StateLayout, *, create: bool) -> StateLayout:
    layout = state_dir if isinstance(state_dir, StateLayout) else StateLayout(Path(state_dir))
    return layout.ensure() if create else layout


def open_writer(
    state_dir: Path | StateLayout,
    *,
    key: SecretStr | None = None,
    encrypt_at_rest: bool = True,
    key_source: str = KeySource.KEYRING.value,
    settings: Settings | None = None,
    prompt: Callable[[], str] | None = None,
    env: Mapping[str, str] | None = None,
) -> LedgerWriter:
    """Open (creating when absent) the ledger below ``state_dir`` for appending.

    ``key`` is a hex master key supplied by the caller; without it the key source of the config
    (``keyring`` by default) supplies one. ``encrypt_at_rest`` mirrors the
    ``privacy.egress.encrypt_at_rest`` setting.
    """
    return LedgerWriter(
        _layout_of(state_dir, create=True),
        key=key,
        encrypt_at_rest=encrypt_at_rest,
        key_source=key_source,
        settings=settings,
        prompt=prompt,
        env=env,
    )


def open_reader(
    state_dir: Path | StateLayout,
    *,
    key: SecretStr | None = None,
    settings: Settings | None = None,
    prompt: Callable[[], str] | None = None,
    env: Mapping[str, str] | None = None,
) -> LedgerReader:
    """Open the ledger below ``state_dir`` for reading (the CLI passes a ``StateLayout``)."""
    return LedgerReader(
        _layout_of(state_dir, create=False), key=key, settings=settings, prompt=prompt, env=env
    )
