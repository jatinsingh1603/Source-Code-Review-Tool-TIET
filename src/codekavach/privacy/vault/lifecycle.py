"""Rotation, destruction and retention of the mapping vault (E10-03).

Owning epic: E10. Invariant I3: these operations move and destroy key material and remove records;
none of them reads a mapping value out of the vault, prints one or exports one.

**Rotation (``rotate_key``).** The envelope keeps one data key that seals every record and a master
key (or a key-management service) that seals only the data key, so changing the master key
rewrites one header field and leaves every ciphertext as it is. The rotation is a header
operation on a *copy*: it takes the write lock, copies the database with SQLite's backup API into
``vault.db.rotating``, changes the header of the copy, fsyncs it and renames it over the original.
Until the rename the original is untouched, so a failure or a kill at any point leaves a vault that
opens with the old key; the leftover copy is removed by the next open (``store.clean_orphans``).
The old key stops working because the header it opened is gone, not because it was erased. Each
rotation is recorded in the ``rotations`` table with a timestamp and the old and new key-source
names, never key material.

With ``new_data_key=True`` the data key itself is replaced: every record is opened and sealed again
under a new key, with a new nonce prefix and a counter that restarts from one, in one transaction
on the copy. That is the expensive option, and it is the one to use after a suspected compromise of
the data key. The decrypted values live in local variables for the length of one row.

A scan must not run while a vault is rotated. The rotation refuses when it cannot take the write
lock at once, and refuses to rename if the file changed under it.

**Destruction (``destroy``).** Crypto-shredding followed by deletion: the sealed data key (and the
sealed salt) are overwritten with random bytes and flushed, so every record becomes unreadable
whatever copies of the ciphertext exist; then the keyring entry and the files are deleted. What it
cannot promise is that no copy of the *old* header exists: a snapshot, a backup, a journal or a
copy-on-write file system may keep blocks. ``DestroyResult.caveats`` says so, and callers print it
as it is. A key held by an external key-management service is not deleted by this code.

**Retention (``apply_retention``).** Mappings of scans older than ``privacy.vault.retention_days``
are deleted, a chunk at a time, each chunk in its own short transaction. The header and the salt
are never touched, so pseudonyms stay stable (I5). The price: the payloads of a removed scan can no
longer be restored, and its ledger entries can no longer be checked against the vault's originals,
which is part of how I6 is shown after the fact. The setting is therefore off by default and is
printed in each report's privacy attestation.
"""

import contextlib
import json
import os
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.timeutil import utc_now
from codekavach.privacy.vault.crypto import (
    RecordCipher,
    build_nonce,
    new_nonce_prefix,
    record_aad,
    wrap_data_key,
)
from codekavach.privacy.vault.crypto import (
    new_data_key as make_data_key,
)
from codekavach.privacy.vault.errors import VaultError, VaultFormatError
from codekavach.privacy.vault.keys import (
    KeySource,
    KmsClient,
    ScryptParams,
    SecretBytes,
    forget_master_key,
    load_kms_source,
    resolve_master_key,
)
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import (
    LIFECYCLE_SCHEMA,
    ORPHAN_SUFFIX,
    SALT_AAD,
    VaultHeader,
    clean_orphans,
    connect,
    read_header,
    unlock_data_key,
)

_LOG = get_logger("codekavach.privacy.vault")
_FETCH: Final = 512
_CHUNK: Final = 2000
CONFIRM_PREFIX: Final = "destroy-"


class DestroyRefusedError(VaultError):
    """``destroy`` was called without the confirmation token of this vault."""


@dataclass(frozen=True, slots=True)
class RotationResult:
    """What a rotation changed; no key material."""

    old_source: str
    new_source: str
    data_key_rotated: bool
    records_reencrypted: int
    rotated_at: str


@dataclass(frozen=True, slots=True)
class DestroyResult:
    """What a destruction removed, and what it cannot promise."""

    records_removed: int
    scans_removed: int
    key_entry_removed: bool
    files_removed: int
    caveats: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetentionResult:
    """What retention removed; ``retention_days`` is the setting that was in force."""

    retention_days: int | None
    scans_removed: int
    records_removed: int
    undated_scans_kept: int


def _require(path: Path) -> VaultHeader:
    header = read_header(path)
    if header is None:
        raise VaultError("there is no vault in this state directory")
    return header


def _sidecars(path: Path) -> list[Path]:
    return [path.with_name(path.name + suffix) for suffix in ("-wal", "-shm", "-journal")]


def _fsync_file(path: Path) -> None:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    """Flush the directory entry of a rename; a platform that cannot open a directory skips it."""
    try:
        descriptor = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _signature(path: Path) -> tuple[int, int, int]:
    """Size and modification time of the database and the size of its log."""
    stat = path.stat()
    log = path.with_name(path.name + "-wal")
    return stat.st_size, stat.st_mtime_ns, log.stat().st_size if log.exists() else 0


def confirmation_token(state_dir: Path) -> str:
    """The token ``destroy`` requires: it names this vault, so it cannot be a constant."""
    return CONFIRM_PREFIX + _require(vault_path(state_dir)).vault_id


# --- rotation -------------------------------------------------------------------------------


def rotate_key(
    state_dir: Path,
    *,
    new_backend: str | None = None,
    new_data_key: bool = False,
    settings: Settings | None = None,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[], str] | None = None,
    new_prompt: Callable[[], str] | None = None,
    key: SecretBytes | None = None,
    new_key: SecretBytes | None = None,
    kms: KmsClient | None = None,
    new_kms: KmsClient | None = None,
    _before_replace: Callable[[], None] | None = None,
) -> RotationResult:
    """Re-seal the vault's data key under a new master key, optionally replacing the data key.

    ``new_backend`` is the key source to move to (``keyring``, ``passphrase``, ``kms``); ``None``
    keeps the source and makes a new key of it (a new passphrase, a new keyring key). The current
    key is resolved from ``settings``, ``prompt`` or ``key``; a new passphrase comes from
    ``new_prompt`` (or ``settings``), a new keyring key is made, and a new key-management key is
    ``new_kms``. ``_before_replace`` is a test seam called after the copy is flushed and before
    it replaces the original.

    Raises:
        VaultError: the vault is busy or missing, a key cannot be resolved, or the file changed.
    """
    path = vault_path(state_dir)
    header = _require(path)
    clean_orphans(path)
    old = KeySource(header.key_source)
    try:
        target = KeySource(new_backend) if new_backend else old
    except ValueError:
        raise VaultError("unknown vault key source") from None
    current = unlock_data_key(
        header,
        source=old,
        key=key,
        settings=settings,
        prompt=prompt,
        env=env,
        kms=(lambda: kms or load_kms_source(settings, env)) if old is KeySource.KMS else None,
    )
    final_key = make_data_key() if new_data_key else current
    vault_id = os.urandom(8).hex() if target is KeySource.KEYRING else header.vault_id
    kdf = ScryptParams.fresh() if target is KeySource.PASSPHRASE else None
    if target is KeySource.KMS:
        wrapped = (new_kms or kms or load_kms_source(settings, env)).wrap(final_key)
    else:
        master = new_key or resolve_master_key(
            target,
            settings=settings,
            prompt=new_prompt or prompt,
            account=f"vault-{vault_id}",
            kdf=kdf,
            env=env,
        )
        wrapped = wrap_data_key(master.reveal(), final_key)
    stamp = utc_now().isoformat()
    temporary = path.with_name(path.name + ORPHAN_SUFFIX)
    try:
        reencrypted = _rewrite(
            path,
            temporary,
            header=header,
            updates={
                "key_source": target.value,
                "kdf": None if kdf is None else json.dumps(kdf.to_json()),
                "wrapped_key": wrapped,
                "vault_id": vault_id,
                "rotated_at": stamp,
            },
            history=(stamp, old.value, target.value, new_data_key),
            reseal=(current, final_key) if new_data_key else None,
            before_replace=_before_replace,
        )
    except BaseException:
        if target is KeySource.KEYRING and vault_id != header.vault_id:
            forget_master_key(target, f"vault-{vault_id}")  # the key of a header never written
        raise
    if old is KeySource.KEYRING or old is KeySource.EPHEMERAL:
        account = f"vault-{header.vault_id}"
        if target is not old or vault_id != header.vault_id:
            forget_master_key(old, account)
    _LOG.info("vault_rotated", old_source=old.value, new_source=target.value, data_key=new_data_key)
    return RotationResult(old.value, target.value, new_data_key, reencrypted, stamp)


def _rewrite(
    path: Path,
    temporary: Path,
    *,
    header: VaultHeader,
    updates: Mapping[str, object],
    history: tuple[str, str, str, bool],
    reseal: tuple[bytes, bytes] | None,
    before_replace: Callable[[], None] | None,
) -> int:
    """Copy ``path`` to ``temporary``, change the header there and rename it over ``path``."""
    guard = sqlite3.connect(path, timeout=0, isolation_level=None)
    try:
        try:
            guard.execute("BEGIN IMMEDIATE")
            guard.execute("ROLLBACK")  # the lock was free; a checkpoint cannot run inside one
            guard.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            guard.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            raise VaultError("the vault is in use; stop the scan and try again") from None
        before = _signature(path)
        _remove(temporary)
        _make_private(temporary)
        copy = sqlite3.connect(temporary, isolation_level=None)
        reader = sqlite3.connect(path, isolation_level=None)
        try:
            reader.backup(copy)  # a reader: the write lock is held by the guard
            count = _change_header(copy, header=header, updates=updates, history=history,
                                   reseal=reseal)  # fmt: skip
        finally:
            reader.close()
            copy.close()
        _fsync_file(temporary)
    except BaseException:
        guard.close()
        _remove(temporary)
        raise
    guard.close()
    for sidecar in _sidecars(path):
        if sidecar.exists() and sidecar.stat().st_size == 0:
            _remove(sidecar)
    if _signature(path) != before:
        _remove(temporary)
        raise VaultError("the vault changed while it was being rotated; try again")
    if before_replace is not None:
        before_replace()
    temporary.replace(path)
    _fsync_directory(path)
    return count


def _make_private(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    os.close(os.open(path, flags, 0o600))


def _remove(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()


def _change_header(
    copy: sqlite3.Connection,
    *,
    header: VaultHeader,
    updates: Mapping[str, object],
    history: tuple[str, str, str, bool],
    reseal: tuple[bytes, bytes] | None,
) -> int:
    copy.execute("PRAGMA secure_delete = ON")
    copy.execute("BEGIN IMMEDIATE")
    try:
        for statement in filter(None, (part.strip() for part in LIFECYCLE_SCHEMA.split(";"))):
            copy.execute(statement)
        count = 0
        fields = dict(updates)
        if reseal is not None:
            count, extra = _reseal_records(copy, header, *reseal)
            fields.update(extra)
        names = ", ".join(f"{name} = ?" for name in fields)
        update = f"UPDATE header SET {names} WHERE id = 1"  # noqa: S608 - fixed column names
        copy.execute(update, tuple(fields.values()))
        copy.execute(
            "INSERT INTO rotations (at, from_source, to_source, data_key_rotated) "
            "VALUES (?, ?, ?, ?)",
            (history[0], history[1], history[2], int(history[3])),
        )
        copy.execute("COMMIT")
    except BaseException:
        with contextlib.suppress(sqlite3.Error):
            copy.execute("ROLLBACK")
        raise
    return count


def _reseal_records(
    copy: sqlite3.Connection, header: VaultHeader, old_key: bytes, new_key: bytes
) -> tuple[int, dict[str, object]]:
    """Open every record under ``old_key`` and seal it under ``new_key`` with fresh nonces."""
    old = RecordCipher(old_key)
    fresh = RecordCipher(new_key)
    prefix = new_nonce_prefix()
    counter = 0
    cursor = copy.execute(
        "SELECT id, scan_id, pseudonym, nonce, ciphertext FROM records ORDER BY id"
    )
    while rows := cursor.fetchmany(_FETCH):
        updates: list[tuple[bytes, bytes, bytes, int]] = []
        for row_id, scan_id, pseudonym, nonce, ciphertext in rows:
            aad = record_aad(scan_id, pseudonym)
            plain = old.open(bytes(nonce), aad, bytes(ciphertext))
            original = json.loads(plain)["o"]
            counter += 1
            sealed_nonce = build_nonce(prefix, counter)
            updates.append(
                (
                    sealed_nonce,
                    fresh.seal(sealed_nonce, aad, plain),
                    fresh.index_hash(original),
                    row_id,
                )
            )
        copy.executemany(
            "UPDATE records SET nonce = ?, ciphertext = ?, original_index = ? WHERE id = ?",
            updates,
        )
    fields: dict[str, object] = {}
    if header.salt_ciphertext is not None and header.salt_nonce is not None:
        salt = old.open(bytes(header.salt_nonce), SALT_AAD, bytes(header.salt_ciphertext))
        counter += 1
        salt_nonce = build_nonce(prefix, counter)
        fields["salt_nonce"] = salt_nonce
        fields["salt_ciphertext"] = fresh.seal(salt_nonce, SALT_AAD, salt)
    fields["nonce_prefix"] = prefix
    fields["nonce_counter"] = counter
    old.close()
    fresh.close()
    return counter - (1 if "salt_nonce" in fields else 0), fields


# --- destruction ----------------------------------------------------------------------------


def destroy(
    state_dir: Path,
    *,
    confirm: str | None = None,
) -> DestroyResult:
    """Crypto-shred and delete the vault. ``confirm`` must equal ``confirmation_token(state_dir)``.

    Raises:
        DestroyRefusedError: no token, or the token of another vault; nothing was changed.
    """
    path = vault_path(state_dir)
    header = _require(path)
    if confirm is None or confirm != CONFIRM_PREFIX + header.vault_id:
        raise DestroyRefusedError("destroying a vault needs its confirmation token")
    connection = connect(path)
    try:
        records = int(connection.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        scans = int(connection.execute("SELECT COUNT(DISTINCT scan_id) FROM records").fetchone()[0])
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE header SET wrapped_key = randomblob(length(wrapped_key)), "
            "salt_ciphertext = CASE WHEN salt_ciphertext IS NULL THEN NULL "
            "ELSE randomblob(length(salt_ciphertext)) END WHERE id = 1"
        )
        connection.execute("COMMIT")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    _fsync_file(path)
    forgot = forget_master_key(header.key_source, f"vault-{header.vault_id}")
    removed = 0
    for target in (path, *_sidecars(path), path.with_name(path.name + ORPHAN_SUFFIX)):
        if target.exists():
            _remove(target)
            removed += 1
    _LOG.info("vault_destroyed", key_source=header.key_source, records=records)
    return DestroyResult(records, scans, forgot, removed, _caveats(header.key_source, forgot))


def _caveats(source: str, forgot: bool) -> tuple[str, ...]:
    notes = [
        "The key is destroyed, so the data is unreadable; the data is not claimed to be erased.",
        "Copies of the vault file made earlier (backups, snapshots, a copy-on-write file system, "
        "the journal) may still hold the old sealed key; they stay readable to anyone who also "
        "holds the old master key.",
    ]
    if source == KeySource.KEYRING.value and not forgot:
        notes.append("The keyring entry could not be removed; delete it with the keyring tool.")
    if source == KeySource.KMS.value:
        notes.append("The key held by the key-management service was not deleted by this command.")
    if source == KeySource.PASSPHRASE.value:
        notes.append("The passphrase is not stored by CodeKavach; anyone who knows it and holds an "
                     "earlier copy of the file can still open that copy.")  # fmt: skip
    return tuple(notes)


# --- retention ------------------------------------------------------------------------------


def apply_retention(
    state_dir: Path,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> RetentionResult:
    """Delete the mappings of scans older than ``privacy.vault.retention_days``.

    A no-op with one informational log line when the setting is ``None`` or there is no vault.
    A scan that is exactly as old as the window is kept. The header and the salt are untouched.
    Records of a scan with no recorded creation time (a vault from before E10-03) are kept and
    counted in ``undated_scans_kept``.
    """
    days = settings.privacy.vault.retention_days
    path = vault_path(state_dir)
    if days is None or not path.is_file():
        _LOG.info("vault_retention_skipped", configured=days is not None)
        return RetentionResult(days, 0, 0, 0)
    if read_header(path) is None:
        return RetentionResult(days, 0, 0, 0)
    cutoff = (now or datetime.now(tz=UTC)) - timedelta(days=days)
    connection = connect(path)
    scans_removed = records_removed = 0
    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in filter(None, (part.strip() for part in LIFECYCLE_SCHEMA.split(";"))):
            connection.execute(statement)
        connection.execute("COMMIT")
        expired = [
            scan_id
            for scan_id, created in connection.execute("SELECT scan_id, created_at FROM scans")
            if _parse(created) < cutoff
        ]
        undated = int(
            connection.execute(
                "SELECT COUNT(DISTINCT scan_id) FROM records "
                "WHERE scan_id NOT IN (SELECT scan_id FROM scans)"
            ).fetchone()[0]
        )
        for scan_id in expired:
            while True:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "DELETE FROM records WHERE id IN "
                    "(SELECT id FROM records WHERE scan_id = ? LIMIT ?)",
                    (scan_id, _CHUNK),
                )
                removed = cursor.rowcount
                if removed < _CHUNK:
                    connection.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
                connection.execute("COMMIT")
                records_removed += removed
                if removed < _CHUNK:
                    break
            scans_removed += 1
    finally:
        connection.close()
    _LOG.info("vault_retention_applied", days=days, scans=scans_removed, records=records_removed)
    return RetentionResult(days, scans_removed, records_removed, undated)


def _parse(stamp: str) -> datetime:
    try:
        moment = datetime.fromisoformat(stamp)
    except ValueError:
        raise VaultFormatError("a scan record of the vault has an invalid time") from None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
