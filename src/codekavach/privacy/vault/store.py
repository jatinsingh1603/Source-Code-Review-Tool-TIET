"""The encrypted mapping vault.

Owning epic: E10 (issue E10-01). Invariant I3: nothing read from here is logged, exported or
serialised outside this package; the only readers are the restore engine and the egress guard.

**What it is.** One SQLite file, ``<state>/vault/vault.db``, created with mode 0o600 in a 0o700
directory. A header row holds the format version, the sealed data key, the key source, the scrypt
record (passphrase only), the nonce prefix and counter, and the sealed project salt. A records
table holds one sealed row per ``(scan_id, pseudonym)``. See ``crypto`` for the envelope, the nonce
strategy and the keyed index.

**What is in the clear.** The scan id, the pseudonym, its kind, the keyed index of the original and
the original's length in characters. The length is the price of ``original_count`` and of the
``min_len`` filter without decrypting; it tells a reader of the file how long each original is,
and nothing else about it.

**Concurrency.** Every write is one ``BEGIN IMMEDIATE`` transaction, which takes SQLite's database
write lock; a second writer, in this process or another, waits (30 s) for it. The nonce counter is
read and written inside that transaction, so no two records ever share a nonce. Two scans of one
project may run at once: their records are keyed by scan id and do not conflict. The journal is
write-ahead, so readers do not block the writer.

**Memory.** Decrypted values live in local variables for as long as the caller keeps them. This is
best effort: a managed runtime cannot promise that a value is erased, so the real controls are the
encrypted file and a short process lifetime. ``iter_originals`` never builds a list of all
originals, and its caller must not persist, log or copy the values beyond the automaton it builds.

**Salt.** ``salt()`` returns the persistent per-project salt, so the same name gets the same
pseudonym in every scan (I5), caches hit and experiments repeat. The cost is that a provider can
link the requests of different scans; ``salt.get_or_create_salt`` also offers a per-scan salt, and
``privacy.pseudonym.link_mode`` a per-request one, each at the cost of cache hits and of
reasoning across slices. None of them is claimed to be safe.
"""

import contextlib
import hmac
import json
import os
import re
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.location import Location
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.core.store.layout import FILE_MODE, secure_mkdir
from codekavach.privacy.pseudonymise.generator import PSEUDONYM_SHAPE, PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch
from codekavach.privacy.vault.crypto import (
    COUNTER_LIMIT,
    RecordCipher,
    build_nonce,
    new_data_key,
    new_nonce_prefix,
    record_aad,
    unwrap_data_key,
    wrap_data_key,
)
from codekavach.privacy.vault.errors import (
    VaultConsistencyError,
    VaultError,
    VaultFormatError,
    VaultKeyError,
)
from codekavach.privacy.vault.keys import (
    KeySource,
    ScryptParams,
    SecretBytes,
    resolve_master_key,
)
from codekavach.privacy.vault.models import MappingRecord

FORMAT_VERSION: Final = 1
CIPHER_NAME: Final = "AES-256-GCM"
BUSY_TIMEOUT_SECONDS: Final = 30.0
_FETCH_SIZE: Final = 256
_SALT_AAD: Final = b"ck-vault-salt-v1"
_PSEUDONYM: Final = re.compile(PSEUDONYM_SHAPE)
_LOG = get_logger("codekavach.privacy.vault")

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS header (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    format_version INTEGER NOT NULL,
    vault_id TEXT NOT NULL,
    key_source TEXT NOT NULL,
    kdf TEXT,
    wrapped_key BLOB NOT NULL,
    nonce_prefix BLOB NOT NULL,
    nonce_counter INTEGER NOT NULL,
    salt_nonce BLOB,
    salt_ciphertext BLOB,
    created_at TEXT NOT NULL,
    rotated_at TEXT
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    pseudonym TEXT NOT NULL,
    kind TEXT NOT NULL,
    original_index BLOB NOT NULL,
    original_length INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    UNIQUE (scan_id, pseudonym)
);
CREATE INDEX IF NOT EXISTS records_pseudonym ON records (pseudonym);
CREATE INDEX IF NOT EXISTS records_original_index ON records (original_index);
"""
_SELECT_HEADER: Final = (
    "SELECT format_version, vault_id, key_source, kdf, wrapped_key, nonce_prefix, nonce_counter, "
    "salt_nonce, salt_ciphertext, created_at, rotated_at FROM header WHERE id = 1"
)
_INSERT_HEADER: Final = (
    "INSERT OR IGNORE INTO header (id, format_version, vault_id, key_source, kdf, wrapped_key, "
    "nonce_prefix, nonce_counter, salt_nonce, salt_ciphertext, created_at, rotated_at) "
    "VALUES (1, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, NULL)"
)


@dataclass(frozen=True, slots=True)
class _Header:
    """The header row; nothing in it is secret except through the key that wraps ``wrapped_key``."""

    format_version: int
    vault_id: str
    key_source: str
    kdf: str | None
    wrapped_key: bytes
    nonce_prefix: bytes
    nonce_counter: int
    salt_nonce: bytes | None
    salt_ciphertext: bytes | None
    created_at: str
    rotated_at: str | None


def _is_locked(error: sqlite3.OperationalError) -> bool:
    return "locked" in str(error) or "busy" in str(error)


def _retry_while_locked[T](action: Callable[[], T]) -> T:
    """Run ``action``, trying again for a while when SQLite says the database is locked.

    SQLite's busy timeout covers ordinary transactions but not every statement: switching the
    journal mode, or reading while another process does that, can fail at once. Two processes
    that create the same vault meet exactly there.
    """
    deadline = time.monotonic() + BUSY_TIMEOUT_SECONDS
    while True:
        try:
            return action()
        except sqlite3.OperationalError as error:
            if not _is_locked(error) or time.monotonic() > deadline:
                raise
            time.sleep(0.02)


def _enable_wal(connection: sqlite3.Connection) -> None:
    """Switch to write-ahead journaling unless the file already uses it (the setting persists)."""
    mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    if str(mode).lower() != "wal":
        connection.execute("PRAGMA journal_mode = WAL")


def _create_private_file(path: Path) -> None:
    """Make an empty file with mode 0o600 in a 0o700 directory; an existing file is kept."""
    secure_mkdir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    os.close(os.open(path, flags, FILE_MODE))


class Vault:
    """Stores and returns pseudonym-to-original mappings under envelope encryption.

    ``key`` overrides the key source (tests, and callers that already hold the master key).
    ``create=False`` refuses to make a new vault. Nothing here appears in a ``repr``.
    """

    def __init__(
        self,
        path: Path,
        key_source: KeySource | str = KeySource.KEYRING,
        key: SecretBytes | None = None,
        *,
        settings: Settings | None = None,
        prompt: Callable[[], str] | None = None,
        env: Mapping[str, str] | None = None,
        create: bool = True,
    ) -> None:
        self._path = Path(path)
        self._settings = settings
        self._prompt = prompt
        self._env = env
        self._key = key
        try:
            self._source = KeySource(key_source)
        except ValueError:
            raise VaultError("unknown vault key source") from None
        header = self._read_header()
        master: SecretBytes | None = None
        if header is None:
            if not create:
                raise VaultError("there is no vault at this path")
            header, master = self._create()
        self._check_header(header)
        self._cipher = RecordCipher(self._unwrap(header, master))
        self._prefix = header.nonce_prefix
        _LOG.info(
            "vault_opened", key_source=header.key_source, format_version=header.format_version
        )

    def __repr__(self) -> str:
        return "Vault(<locked contents>)"

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def path(self) -> Path:
        """Where the vault file is."""
        return self._path

    def close(self) -> None:
        """Drop the key references; later calls raise ``VaultKeyError``."""
        self._cipher.close()
        self._key = None

    # --- opening and creating -------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=BUSY_TIMEOUT_SECONDS, isolation_level=None)
        connection.execute("PRAGMA secure_delete = ON")
        return connection

    def _read_header(self) -> _Header | None:
        if not self._path.is_file():
            return None
        connection = self._connect()
        try:
            row = _retry_while_locked(lambda: connection.execute(_SELECT_HEADER).fetchone())
        except sqlite3.OperationalError as error:
            if "no such table" in str(error):
                return None
            if _is_locked(error):
                raise VaultError("the vault is busy; try again") from None
            raise VaultFormatError("this file is not a vault") from None
        except sqlite3.DatabaseError:
            raise VaultFormatError("this file is not a vault") from None
        finally:
            connection.close()
        return None if row is None else _Header(*row)

    def _create(self) -> tuple[_Header, SecretBytes | None]:
        vault_id = os.urandom(8).hex()
        kdf = ScryptParams.fresh() if self._source is KeySource.PASSPHRASE else None
        master = self._key or resolve_master_key(
            self._source,
            settings=self._settings,
            prompt=self._prompt,
            account=f"vault-{vault_id}",
            kdf=kdf,
            env=self._env,
        )
        wrapped = wrap_data_key(master.reveal(), new_data_key())
        _create_private_file(self._path)
        connection = self._connect()
        try:
            _retry_while_locked(lambda: _enable_wal(connection))
            connection.execute("BEGIN IMMEDIATE")
            for statement in filter(None, (part.strip() for part in _SCHEMA.split(";"))):
                connection.execute(statement)
            connection.execute(
                _INSERT_HEADER,
                (
                    FORMAT_VERSION,
                    vault_id,
                    self._source.value,
                    None if kdf is None else json.dumps(kdf.to_json()),
                    wrapped,
                    new_nonce_prefix(),
                    utc_now().isoformat(),
                ),
            )
            connection.execute("COMMIT")
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        header = self._read_header()
        if header is None:
            raise VaultFormatError("the vault could not be created")
        # Another process may have created it first; then its vault id, not ours, names the key.
        return header, master if header.vault_id == vault_id else None

    @staticmethod
    def _check_header(header: _Header) -> None:
        if header.format_version != FORMAT_VERSION:
            raise VaultFormatError("this vault has a format this version cannot read")
        if len(header.nonce_prefix) != 4 or not 0 <= header.nonce_counter <= COUNTER_LIMIT:
            raise VaultFormatError("the header of this vault is invalid")

    def _unwrap(self, header: _Header, master: SecretBytes | None) -> bytes:
        if master is None:
            if self._key is not None:
                master = self._key
            else:
                if header.key_source != self._source.value:
                    raise VaultKeyError(f"this vault uses the {header.key_source} key source")
                kdf = None if header.kdf is None else ScryptParams.from_json(json.loads(header.kdf))
                master = resolve_master_key(
                    self._source,
                    settings=self._settings,
                    prompt=self._prompt,
                    account=f"vault-{header.vault_id}",
                    kdf=kdf,
                    env=self._env,
                    create=False,
                )
        return unwrap_data_key(master.reveal(), header.wrapped_key)

    # --- transactions ---------------------------------------------------------------------

    @contextlib.contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")
        finally:
            connection.close()

    def _counter(self, connection: sqlite3.Connection) -> int:
        """The last nonce number handed out; refuses a counter that has gone backwards."""
        row = connection.execute("SELECT nonce_counter FROM header WHERE id = 1").fetchone()
        used = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        if row is None or row[0] < used:
            raise VaultFormatError("the nonce counter of this vault is behind its records")
        counter: int = row[0]
        return counter

    def _nonce(self, number: int) -> bytes:
        return build_nonce(self._prefix, number)

    # --- mappings -------------------------------------------------------------------------

    def put(self, batch: MappingBatch) -> None:
        """Store a scan's mappings in one transaction.

        Idempotent on ``(scan_id, pseudonym)``: the same pair again changes nothing. A different
        original for a pseudonym already stored in that scan means the generator collided; the
        whole batch is rolled back and ``VaultConsistencyError`` is raised.
        """
        if not batch.entries:
            return
        if not batch.scan_id or len(batch.scan_id) > 128:
            raise VaultError("a batch needs a scan id")
        added = 0
        with self._write() as connection:
            counter = self._counter(connection)
            for entry in batch.entries:
                if not _PSEUDONYM.match(entry.pseudonym) or not entry.original:
                    raise VaultError("a mapping needs a pseudonym of the generator's shape")
                index = self._cipher.index_hash(entry.original)
                existing = connection.execute(
                    "SELECT original_index FROM records WHERE scan_id = ? AND pseudonym = ?",
                    (batch.scan_id, entry.pseudonym),
                ).fetchone()
                if existing is not None:
                    if not hmac.compare_digest(existing[0], index):
                        raise VaultConsistencyError(
                            "one pseudonym of this scan would stand for two different originals"
                        )
                    continue
                counter += 1
                nonce = self._nonce(counter)
                sealed = self._cipher.seal(
                    nonce,
                    record_aad(batch.scan_id, entry.pseudonym),
                    _encode_payload(entry.original, entry.scope, entry.first_location),
                )
                connection.execute(
                    "INSERT INTO records (scan_id, pseudonym, kind, original_index, "
                    "original_length, nonce, ciphertext) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        batch.scan_id,
                        entry.pseudonym,
                        PseudonymKind(entry.kind).value,
                        index,
                        len(entry.original),
                        nonce,
                        sealed,
                    ),
                )
                added += 1
            connection.execute("UPDATE header SET nonce_counter = ? WHERE id = 1", (counter,))
        _LOG.info("vault_put", scan_id=batch.scan_id, added=added, unchanged=len(batch) - added)

    def get_record(self, pseudonym: str, *, scan_id: str | None = None) -> MappingRecord | None:
        """The newest record of ``pseudonym`` (of ``scan_id`` when given), or ``None``."""
        sql = "SELECT scan_id, pseudonym, kind, nonce, ciphertext FROM records WHERE pseudonym = ?"
        args: tuple[Any, ...] = (pseudonym,)
        if scan_id is not None:
            sql += " AND scan_id = ?"
            args += (scan_id,)
        connection = self._connect()
        try:
            row = connection.execute(sql + " ORDER BY id DESC LIMIT 1", args).fetchone()
        finally:
            connection.close()
        return None if row is None else self._record(*row)

    def lookup(self, pseudonym: str, *, scan_id: str | None = None) -> str | None:
        """The original behind ``pseudonym``, or ``None``.

        With a persistent salt the same pseudonym stands for the same original in every scan;
        with a per-scan salt it need not, so pass ``scan_id`` when the scan is known.
        """
        record = self.get_record(pseudonym, scan_id=scan_id)
        return None if record is None else record.original

    def lookup_many(
        self, pseudonyms: Iterable[str], *, scan_id: str | None = None
    ) -> dict[str, str]:
        """The originals behind several pseudonyms, in one query; unknown names are left out.

        With ``scan_id`` only that scan's records are read. Without it the newest record of each
        name wins, as in ``lookup``. Only the record that wins is decrypted.
        """
        names = list(dict.fromkeys(pseudonyms))
        if not names:
            return {}
        marks = ",".join(["?"] * len(names))
        sql = (
            "SELECT scan_id, pseudonym, nonce, ciphertext FROM records "  # noqa: S608 - only "?" marks
            f"WHERE pseudonym IN ({marks})"
        )
        args: list[Any] = list(names)
        if scan_id is not None:
            sql += " AND scan_id = ?"
            args.append(scan_id)
        connection = self._connect()
        try:
            rows = connection.execute(sql + " ORDER BY id DESC", args).fetchall()
        finally:
            connection.close()
        found: dict[str, str] = {}
        for row_scan, pseudonym, nonce, ciphertext in rows:
            if pseudonym in found:
                continue
            found[pseudonym] = self._payload(row_scan, pseudonym, nonce, ciphertext)["o"]
        return found

    def reverse(self, original: str, *, scan_id: str | None = None) -> str | None:
        """The pseudonym of ``original`` (newest first), found by its keyed index."""
        sql = "SELECT pseudonym FROM records WHERE original_index = ?"
        args: tuple[Any, ...] = (self._cipher.index_hash(original),)
        if scan_id is not None:
            sql += " AND scan_id = ?"
            args += (scan_id,)
        connection = self._connect()
        try:
            row = connection.execute(sql + " ORDER BY id DESC LIMIT 1", args).fetchone()
        finally:
            connection.close()
        pseudonym: str | None = None if row is None else row[0]
        return pseudonym

    def iter_originals(self, *, min_len: int = 4) -> Iterator[str]:
        """Yield each distinct stored original of at least ``min_len`` characters, lazily.

        For the egress guard's automaton. The caller must not persist, log or copy the values
        beyond that automaton, and must not collect them into a list that outlives it.
        """
        if min_len < 0:
            raise ValueError("min_len is not negative")
        connection = self._connect()
        try:
            cursor = connection.execute(
                "SELECT scan_id, pseudonym, nonce, ciphertext FROM records "
                "WHERE original_length >= ? AND id IN "
                "(SELECT MIN(id) FROM records GROUP BY original_index) ORDER BY id",
                (min_len,),
            )
            while rows := cursor.fetchmany(_FETCH_SIZE):
                for scan_id, pseudonym, nonce, ciphertext in rows:
                    yield self._payload(scan_id, pseudonym, nonce, ciphertext)["o"]
        finally:
            connection.close()

    def original_count(self, min_len: int = 4) -> int:
        """How many distinct originals have at least ``min_len`` characters; decrypts nothing."""
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(DISTINCT original_index) FROM records WHERE original_length >= ?",
                (min_len,),
            ).fetchone()
        finally:
            connection.close()
        count: int = row[0]
        return count

    # --- the project salt -----------------------------------------------------------------

    def salt(self) -> ScanSalt:
        """The persistent per-project salt, made on first use and kept sealed in the header."""
        connection = self._connect()
        try:
            sealed = self._salt_row(connection)
        finally:
            connection.close()
        if sealed is None:
            with self._write() as writer:
                sealed = self._salt_row(writer)
                if sealed is None:
                    counter = self._counter(writer) + 1
                    nonce = self._nonce(counter)
                    value = ScanSalt.generate()
                    ciphertext = self._cipher.seal(nonce, _SALT_AAD, value.reveal())
                    writer.execute(
                        "UPDATE header SET nonce_counter = ?, salt_nonce = ?, "
                        "salt_ciphertext = ? WHERE id = 1",
                        (counter, nonce, ciphertext),
                    )
                    return value
        return ScanSalt(self._cipher.open(sealed[0], _SALT_AAD, sealed[1]))

    @staticmethod
    def _salt_row(connection: sqlite3.Connection) -> tuple[bytes, bytes] | None:
        row = connection.execute(
            "SELECT salt_nonce, salt_ciphertext FROM header WHERE id = 1"
        ).fetchone()
        if row is None or row[0] is None or row[1] is None:
            return None
        return bytes(row[0]), bytes(row[1])

    # --- decryption -----------------------------------------------------------------------

    def _payload(
        self, scan_id: str, pseudonym: str, nonce: bytes, ciphertext: bytes
    ) -> dict[str, Any]:
        plain = self._cipher.open(bytes(nonce), record_aad(scan_id, pseudonym), bytes(ciphertext))
        data = json.loads(plain)
        if not isinstance(data, dict) or not isinstance(data.get("o"), str):
            raise VaultFormatError("a vault record has an unexpected shape")
        return data

    def _record(
        self, scan_id: str, pseudonym: str, kind: str, nonce: bytes, ciphertext: bytes
    ) -> MappingRecord:
        data = self._payload(scan_id, pseudonym, nonce, ciphertext)
        location = data.get("l")
        return MappingRecord(
            pseudonym=pseudonym,
            original=data["o"],
            kind=PseudonymKind(kind),
            scope=str(data.get("s", "")),
            first_location=None if location is None else Location.model_validate_json(location),
        )


def _encode_payload(original: str, scope: str, location: Location | None) -> bytes:
    document = {
        "o": original,
        "s": scope,
        "l": None if location is None else location.model_dump_json(),
    }
    return json.dumps(document).encode("ascii")
