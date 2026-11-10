"""What can be said about a vault without opening it (E10-03).

Owning epic: E10. Invariant I3: nothing here reads, decrypts, prints or exports a mapping value.

**Status does not unlock.** An operator asking "is there a vault and how big is it?" must not need a
passphrase, and a monitoring script must never hold a master key. Every field of ``VaultInfo``
therefore comes from the unencrypted header, from a count over the records table, or from file
metadata. The one field that touches a key is ``key_available``: a probe that tries to unseal the
*data key* with the vault's own key source and reports success or failure. It decrypts no record,
and it is off with ``probe=False`` (a passphrase probe costs one key derivation, about 0.1 s).

**What the header holds.** Format version, a random vault id, the key source, the key-derivation
record (salt and cost, no key), the sealed data key, the nonce prefix and counter, the sealed salt,
two timestamps, and counts derived from the tables. It holds no project path, no file name and no
scan content: a test reads the file and asserts that.
"""

import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.privacy.vault.errors import VaultError
from codekavach.privacy.vault.keys import KeySource, KmsClient, load_kms_source
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import VaultHeader, connect, read_header, unlock_data_key

_LOG = get_logger("codekavach.privacy.vault")
_NO_TABLE: Final = "no such table"


@dataclass(frozen=True, slots=True)
class VaultInfo:
    """Metadata of one vault; none of it is secret and none of it comes from a decrypted record."""

    path: Path
    format_version: int
    key_source: str
    record_count: int
    scan_count: int
    created_at: str
    last_write_at: str | None
    rotated_at: str | None
    rotation_count: int
    retention_days: int | None
    key_available: bool | None


def count_rows(path: Path) -> tuple[int, int, int]:
    """``(records, distinct scans, rotations)`` of the vault file; no value is read."""
    connection = connect(path)
    try:
        records = int(connection.execute("SELECT COUNT(*) FROM records").fetchone()[0])
        scans = int(connection.execute("SELECT COUNT(DISTINCT scan_id) FROM records").fetchone()[0])
        try:
            rotations = int(connection.execute("SELECT COUNT(*) FROM rotations").fetchone()[0])
        except sqlite3.OperationalError as error:
            if _NO_TABLE not in str(error):
                raise
            rotations = 0
    finally:
        connection.close()
    return records, scans, rotations


def last_write(path: Path) -> str | None:
    """When the vault file (or its write-ahead log) was last written, from the file system."""
    stamps = []
    for candidate in (path, path.with_name(path.name + "-wal")):
        try:
            stamps.append(candidate.stat().st_mtime)
        except OSError:
            continue
    if not stamps:
        return None
    return datetime.fromtimestamp(max(stamps), tz=UTC).isoformat()


def vault_info(
    state_dir: Path,
    *,
    settings: Settings | None = None,
    env: Mapping[str, str] | None = None,
    prompt: Callable[[], str] | None = None,
    kms: KmsClient | None = None,
    probe: bool = True,
) -> VaultInfo:
    """The metadata of the vault under ``state_dir``, without unlocking it.

    ``settings`` supplies the retention setting and the credentials a probe needs; without them
    the retention is ``None`` and the probe reports whether the key source could be reached with
    what is at hand. ``probe=False`` skips the probe (``key_available`` is then ``None``).

    Raises:
        VaultError: there is no vault under ``state_dir``, or the file is not a vault.
    """
    path = vault_path(state_dir)
    header = read_header(path)
    if header is None:
        raise VaultError("there is no vault in this state directory")
    records, scans, rotations = count_rows(path)
    available: bool | None = None
    if probe:
        available = _probe(header, settings=settings, prompt=prompt, env=env, kms=kms)
    return VaultInfo(
        path=path,
        format_version=header.format_version,
        key_source=header.key_source,
        record_count=records,
        scan_count=scans,
        created_at=header.created_at,
        last_write_at=last_write(path),
        rotated_at=header.rotated_at,
        rotation_count=rotations,
        retention_days=None if settings is None else settings.privacy.vault.retention_days,
        key_available=available,
    )


def _probe(
    header: VaultHeader,
    *,
    settings: Settings | None,
    prompt: Callable[[], str] | None,
    env: Mapping[str, str] | None,
    kms: KmsClient | None,
) -> bool:
    """Whether the data key can be unsealed now; no record is touched, no detail is kept."""
    try:
        source = KeySource(header.key_source)
    except ValueError:
        return False

    def client() -> KmsClient:
        return kms or load_kms_source(settings, env)

    try:
        unlock_data_key(
            header,
            source=source,
            settings=settings,
            prompt=prompt,
            env=env,
            kms=client if source is KeySource.KMS else None,
        )
    except (VaultError, OSError, ValueError, KeyError):
        return False
    _LOG.info("vault_probe", key_source=header.key_source, available=True)
    return True
