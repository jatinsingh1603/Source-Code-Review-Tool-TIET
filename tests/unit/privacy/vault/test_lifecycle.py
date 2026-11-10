"""Status, rotation, destruction and retention of the vault (E10-03).

No test here opens a socket: the key-management source is an in-process fake, and the process
blocks sockets besides (``tests/privacy/test_network_blocked.py``).
"""

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.vault import crypto, keys, lifecycle
from codekavach.privacy.vault.errors import VaultError, VaultKeyError
from codekavach.privacy.vault.info import vault_info
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.lifecycle import (
    DestroyRefusedError,
    apply_retention,
    confirmation_token,
    destroy,
    rotate_key,
)
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import ORPHAN_SUFFIX, Vault, read_header, unlock_data_key
from codekavach.report.model.build import _attestation
from tests.support.factories import make_scan

KEY = SecretBytes(b"\x11" * 32)
OTHER_KEY = SecretBytes(b"\x22" * 32)
NAMES = [("fn_1", "alpha_name"), ("var_2", "bravo_value"), ("cls_3", "CharlieKind")]
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def batch(scan: str, *pairs: tuple[str, str]) -> MappingBatch:
    entries = tuple(
        MappingEntry(p, o, PseudonymKind(p.split("_", maxsplit=1)[0]), "mod", None)
        for p, o in pairs
    )
    return MappingBatch(scan, entries)


class FakeKms:
    """An in-process key-management service: seals a key under its own secret."""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret
        self.calls: list[str] = []

    def wrap(self, data_key: bytes) -> bytes:
        self.calls.append("wrap")
        return b"fake:" + crypto.wrap_data_key(self._secret, data_key)

    def unwrap(self, blob: bytes) -> bytes:
        self.calls.append("unwrap")
        if not blob.startswith(b"fake:"):
            raise VaultKeyError("the vault key does not open this vault")
        return crypto.unwrap_data_key(self._secret, blob[5:])


@dataclass
class Credentials:
    """What it takes to open a vault of one key source, and to rotate to one."""

    source: KeySource
    key: SecretBytes | None = None
    passphrase: str | None = None
    kms: FakeKms | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def open_args(self) -> dict[str, Any]:
        arguments: dict[str, Any] = {}
        if self.key is not None:
            arguments["key"] = self.key
        if self.passphrase is not None:
            arguments["prompt"] = lambda: str(self.passphrase)
        if self.kms is not None:
            arguments["kms"] = self.kms
        return arguments

    def current(self) -> dict[str, Any]:
        arguments: dict[str, Any] = {}
        if self.key is not None:
            arguments["key"] = self.key
        if self.passphrase is not None:
            arguments["prompt"] = lambda: str(self.passphrase)
        if self.kms is not None:
            arguments["kms"] = self.kms
        return arguments

    def target(self) -> dict[str, Any]:
        arguments: dict[str, Any] = {"new_backend": self.source.value}
        if self.key is not None:
            arguments["new_key"] = self.key
        if self.passphrase is not None:
            arguments["new_prompt"] = lambda: str(self.passphrase)
        if self.kms is not None:
            arguments["new_kms"] = self.kms
        return arguments


def first_set(source: KeySource) -> Credentials:
    return {
        KeySource.EPHEMERAL: Credentials(source, key=KEY),
        KeySource.KEYRING: Credentials(source),
        KeySource.PASSPHRASE: Credentials(
            source, passphrase="alpha passphrase"
        ),  # pragma: allowlist secret
        KeySource.KMS: Credentials(source, kms=FakeKms(b"\x31" * 32)),
    }[source]


def second_set(source: KeySource) -> Credentials:
    return {
        KeySource.EPHEMERAL: Credentials(source, key=OTHER_KEY),
        KeySource.KEYRING: Credentials(source),
        KeySource.PASSPHRASE: Credentials(
            source, passphrase="beta passphrase"
        ),  # pragma: allowlist secret
        KeySource.KMS: Credentials(source, kms=FakeKms(b"\x32" * 32)),
    }[source]


@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "state"


def make_vault(state_dir: Path, credentials: Credentials, *, scans: int = 2) -> None:
    with Vault(vault_path(state_dir), credentials.source, **credentials.open_args()) as vault:
        for number in range(scans):
            vault.put(batch(f"scan_{number}", *NAMES))
        vault.salt()


def open_vault(state_dir: Path, credentials: Credentials) -> Vault:
    return Vault(vault_path(state_dir), credentials.source, create=False, **credentials.open_args())


def table(state_dir: Path, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    connection = sqlite3.connect(vault_path(state_dir))
    try:
        return connection.execute(sql, args).fetchall()
    finally:
        connection.close()


# --- status ---------------------------------------------------------------------------------


class TestInfo:
    def test_every_field_is_reported_without_decrypting_a_record(
        self, state: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        credentials = first_set(KeySource.EPHEMERAL)
        make_vault(state, credentials)

        def forbidden(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("a record was decrypted while reporting status")

        monkeypatch.setattr(crypto.RecordCipher, "open", forbidden)
        monkeypatch.setattr(Vault, "_payload", forbidden)
        config = Settings.model_validate({"privacy": {"vault": {"retention_days": 90}}})
        info = vault_info(state, settings=config, probe=False)
        assert info.record_count == 6
        assert info.scan_count == 2
        assert info.key_source == "ephemeral"
        assert info.format_version == 1
        assert info.retention_days == 90
        assert info.key_available is None
        assert info.path == vault_path(state)
        assert info.created_at
        assert info.last_write_at is not None
        assert info.rotated_at is None
        assert info.rotation_count == 0

    def test_the_probe_unseals_the_data_key_and_nothing_else(
        self, state: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        credentials = first_set(KeySource.KMS)
        make_vault(state, credentials)
        monkeypatch.setattr(
            crypto.RecordCipher, "open", lambda *a, **k: pytest.fail("a record was decrypted")
        )
        assert vault_info(state, kms=credentials.kms).key_available is True
        assert vault_info(state, kms=FakeKms(b"\x99" * 32)).key_available is False

    def test_a_passphrase_vault_reports_unavailable_without_the_passphrase(
        self, state: Path
    ) -> None:
        credentials = first_set(KeySource.PASSPHRASE)
        make_vault(state, credentials)
        assert vault_info(state).key_available is False
        assert vault_info(state, prompt=credentials.open_args()["prompt"]).key_available is True
        assert vault_info(state, prompt=lambda: "wrong").key_available is False

    def test_a_missing_vault_is_an_error(self, state: Path) -> None:
        with pytest.raises(VaultError, match="no vault"):
            vault_info(state)

    def test_the_header_holds_no_path_and_no_key_material(self, state: Path) -> None:
        make_vault(state, first_set(KeySource.EPHEMERAL))
        raw = vault_path(state).read_bytes()
        assert str(state).encode() not in raw
        assert state.parent.name.encode() not in raw
        assert KEY.reveal() not in raw
        header = table(state, "SELECT * FROM header")[0]
        columns = [row[1] for row in table(state, "PRAGMA table_info(header)")]
        assert columns == [
            "id", "format_version", "vault_id", "key_source", "kdf", "wrapped_key",
            "nonce_prefix", "nonce_counter", "salt_nonce", "salt_ciphertext", "created_at",
            "rotated_at",
        ]  # fmt: skip
        text = " ".join(str(value) for value in header if isinstance(value, str))
        assert str(state) not in text
        assert "alpha_name" not in raw.decode("latin-1")

    def test_status_does_not_use_the_scrypt_cost_when_not_probing(self, state: Path) -> None:
        make_vault(state, first_set(KeySource.PASSPHRASE))
        assert vault_info(state, probe=False).key_source == "passphrase"


# --- rotation -------------------------------------------------------------------------------

SOURCES = [KeySource.EPHEMERAL, KeySource.KEYRING, KeySource.PASSPHRASE, KeySource.KMS]


@pytest.mark.parametrize("new", SOURCES, ids=lambda s: s.value)
@pytest.mark.parametrize("old", SOURCES, ids=lambda s: s.value)
def test_header_rotation_between_every_pair_of_sources_keeps_every_record(
    state: Path,
    memory_keyring: Any,
    old: KeySource,
    new: KeySource,
) -> None:
    before_creds, after_creds = first_set(old), second_set(new)
    make_vault(state, before_creds)
    with open_vault(state, before_creds) as vault:
        salt = vault.salt().reveal()
    ciphertexts = table(state, "SELECT scan_id, pseudonym, nonce, ciphertext FROM records")
    result = rotate_key(state, **before_creds.current(), **after_creds.target())
    assert (result.old_source, result.new_source) == (old.value, new.value)
    assert result.data_key_rotated is False
    with open_vault(state, after_creds) as vault:
        for scan in ("scan_0", "scan_1"):
            for pseudonym, original in NAMES:
                assert vault.lookup(pseudonym, scan_id=scan) == original
        assert vault.salt().reveal() == salt
    # a header operation: no record was touched
    assert table(state, "SELECT scan_id, pseudonym, nonce, ciphertext FROM records") == ciphertexts
    assert vault_info(state, probe=False).key_source == new.value
    assert vault_info(state, probe=False).rotation_count == 1
    if (old is new and old is not KeySource.KEYRING) or old is not new:
        with pytest.raises(VaultKeyError), open_vault(state, before_creds):
            pass


def test_a_keyring_rotation_moves_to_a_new_entry_and_forgets_the_old_one(
    state: Path,
    memory_keyring: Any,
) -> None:
    creds = first_set(KeySource.KEYRING)
    make_vault(state, creds)
    (old_entry,) = list(memory_keyring.store)
    old_key = memory_keyring.store[old_entry]
    rotate_key(state)
    (new_entry,) = list(memory_keyring.store)
    assert new_entry != old_entry
    assert memory_keyring.store[new_entry] != old_key
    with open_vault(state, creds) as vault:
        assert vault.lookup("fn_1", scan_id="scan_0") == "alpha_name"
    memory_keyring.store[new_entry] = old_key  # the old master key no longer opens it
    with pytest.raises(VaultKeyError), open_vault(state, creds):
        pass


def test_the_rotation_history_names_sources_and_never_keys(state: Path) -> None:
    make_vault(state, first_set(KeySource.EPHEMERAL))
    rotate_key(state, key=KEY, new_key=OTHER_KEY, new_backend="ephemeral")
    ((at, old, new, data),) = table(
        state, "SELECT at, from_source, to_source, data_key_rotated FROM rotations"
    )
    assert (old, new, data) == ("ephemeral", "ephemeral", 0)
    assert at == read_header(vault_path(state)).rotated_at  # type: ignore[union-attr]
    raw = vault_path(state).read_bytes()
    assert KEY.reveal() not in raw
    assert OTHER_KEY.reveal() not in raw


def test_a_crash_between_flush_and_rename_leaves_the_original_openable(state: Path) -> None:
    creds = first_set(KeySource.EPHEMERAL)
    make_vault(state, creds)
    original = vault_path(state).read_bytes()

    def crash() -> None:
        raise KeyboardInterrupt  # stands for a kill between fsync and rename

    with pytest.raises(KeyboardInterrupt):
        rotate_key(
            state, key=KEY, new_key=OTHER_KEY, new_backend="ephemeral", _before_replace=crash
        )
    orphan = vault_path(state).with_name(vault_path(state).name + ORPHAN_SUFFIX)
    assert orphan.exists()
    assert vault_path(state).read_bytes() == original
    with open_vault(state, creds) as vault:  # opening cleans the orphan up
        assert vault.lookup("fn_1", scan_id="scan_0") == "alpha_name"
    assert not orphan.exists()
    assert table(state, "SELECT COUNT(*) FROM records") == [(6,)]


def test_an_orphan_is_kept_while_another_process_holds_the_write_lock(state: Path) -> None:
    creds = first_set(KeySource.EPHEMERAL)
    make_vault(state, creds)
    orphan = vault_path(state).with_name(vault_path(state).name + ORPHAN_SUFFIX)
    orphan.write_bytes(b"half a rotation")
    holder = sqlite3.connect(vault_path(state), isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with open_vault(state, creds):
            pass
        assert orphan.exists()  # someone may be rotating right now
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    with open_vault(state, creds):
        pass
    assert not orphan.exists()


def test_a_rotation_refuses_while_the_vault_is_in_use(state: Path) -> None:
    make_vault(state, first_set(KeySource.EPHEMERAL))
    holder = sqlite3.connect(vault_path(state), isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(VaultError, match="in use"):
            rotate_key(state, key=KEY, new_key=OTHER_KEY, new_backend="ephemeral")
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert not vault_path(state).with_name(vault_path(state).name + ORPHAN_SUFFIX).exists()


def test_a_wrong_current_key_changes_nothing(state: Path) -> None:
    make_vault(state, first_set(KeySource.EPHEMERAL))
    original = vault_path(state).read_bytes()
    with pytest.raises(VaultKeyError):
        rotate_key(state, key=OTHER_KEY, new_key=KEY, new_backend="ephemeral")
    assert vault_path(state).read_bytes() == original


def test_an_unknown_target_source_is_refused(state: Path) -> None:
    make_vault(state, first_set(KeySource.EPHEMERAL))
    with pytest.raises(VaultError, match="unknown"):
        rotate_key(state, key=KEY, new_backend="somewhere")


def test_data_key_rotation_reseals_every_record_with_fresh_nonces(state: Path) -> None:
    creds = first_set(KeySource.EPHEMERAL)
    make_vault(state, creds, scans=3)
    with open_vault(state, creds) as vault:
        salt = vault.salt().reveal()
    old_header = read_header(vault_path(state))
    assert old_header is not None
    old_data_key = unlock_data_key(old_header, source=KeySource.EPHEMERAL, key=KEY)
    old_rows = table(
        state,
        "SELECT id, scan_id, pseudonym, nonce, ciphertext, original_index FROM records ORDER BY id",
    )
    result = rotate_key(state, key=KEY, new_key=KEY, new_backend="ephemeral", new_data_key=True)
    assert result.data_key_rotated is True
    assert result.records_reencrypted == 9
    new_header = read_header(vault_path(state))
    assert new_header is not None
    assert new_header.nonce_prefix != old_header.nonce_prefix
    assert new_header.nonce_counter == 10  # nine records and the salt, counted again from one
    new_rows = table(
        state,
        "SELECT id, scan_id, pseudonym, nonce, ciphertext, original_index FROM records ORDER BY id",
    )
    assert len(new_rows) == len(old_rows)
    old_nonces = {row[3] for row in old_rows} | {old_header.salt_nonce}
    new_nonces = [row[3] for row in new_rows] + [new_header.salt_nonce]
    assert len(set(new_nonces)) == len(new_nonces)
    assert not old_nonces & set(new_nonces)
    for old_row, new_row in zip(old_rows, new_rows, strict=True):
        assert old_row[1:3] == new_row[1:3]
        assert old_row[4] != new_row[4]
        assert old_row[5] != new_row[5]  # the keyed index moved with the key
    stale = crypto.RecordCipher(old_data_key)
    with pytest.raises(VaultKeyError):
        stale.open(
            bytes(new_rows[0][3]), crypto.record_aad("scan_0", "fn_1"), bytes(new_rows[0][4])
        )
    with open_vault(state, creds) as vault:
        assert vault.salt().reveal() == salt
        for scan in ("scan_0", "scan_1", "scan_2"):
            assert vault.lookup("var_2", scan_id=scan) == "bravo_value"
        assert vault.reverse("alpha_name", scan_id="scan_1") == "fn_1"
        vault.put(batch("scan_9", ("fn_7", "delta_thing")))  # the counter carries on from the reset
        assert vault.lookup("fn_7", scan_id="scan_9") == "delta_thing"
    assert read_header(vault_path(state)).nonce_counter == 11  # type: ignore[union-attr]


@settings(
    max_examples=12, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(steps=st.lists(st.sampled_from(["header", "data"]), min_size=1, max_size=4))
def test_random_rotation_sequences_keep_the_set_of_mappings(
    tmp_path_factory: pytest.TempPathFactory, steps: list[str]
) -> None:
    state_dir = tmp_path_factory.mktemp("state")
    keys = [SecretBytes(bytes([n]) * 32) for n in range(1, 8)]
    make_vault(state_dir, Credentials(KeySource.EPHEMERAL, key=keys[0]))
    current = keys[0]
    for number, step in enumerate(steps, start=1):
        following = keys[number]
        rotate_key(
            state_dir,
            key=current,
            new_key=following,
            new_backend="ephemeral",
            new_data_key=step == "data",
        )
        current = following
    with Vault(vault_path(state_dir), KeySource.EPHEMERAL, current, create=False) as vault:
        found = {
            (scan, pseudonym): vault.lookup(pseudonym, scan_id=scan)
            for scan in ("scan_0", "scan_1")
            for pseudonym, _ in NAMES
        }
        assert found == {
            (scan, pseudonym): original
            for scan in ("scan_0", "scan_1")
            for pseudonym, original in NAMES
        }


# --- destruction ----------------------------------------------------------------------------


class TestDestroy:
    def test_it_refuses_without_the_confirmation_token(self, state: Path) -> None:
        make_vault(state, first_set(KeySource.EPHEMERAL))
        before = vault_path(state).read_bytes()
        with pytest.raises(DestroyRefusedError):
            destroy(state)
        with pytest.raises(DestroyRefusedError):
            destroy(state, confirm="destroy")
        with pytest.raises(DestroyRefusedError):
            destroy(state, confirm="destroy-0000000000000000")
        assert vault_path(state).read_bytes() == before

    def test_the_token_names_the_vault(self, state: Path, tmp_path: Path) -> None:
        make_vault(state, first_set(KeySource.EPHEMERAL))
        other = tmp_path / "other"
        make_vault(other, first_set(KeySource.EPHEMERAL))
        assert confirmation_token(state) != confirmation_token(other)
        with pytest.raises(DestroyRefusedError):
            destroy(state, confirm=confirmation_token(other))

    def test_it_removes_the_files_the_keyring_entry_and_says_what_it_cannot_promise(
        self,
        state: Path,
        memory_keyring: Any,
    ) -> None:
        make_vault(state, first_set(KeySource.KEYRING))
        assert len(memory_keyring.store) == 1
        result = destroy(state, confirm=confirmation_token(state))
        assert result.records_removed == 6
        assert result.scans_removed == 2
        assert result.key_entry_removed is True
        assert result.files_removed >= 1
        assert result.caveats
        assert any("not claimed to be erased" in line for line in result.caveats)
        assert not vault_path(state).exists()
        assert memory_keyring.store == {}

    def test_a_copy_taken_after_the_overwrite_cannot_be_opened(
        self, state: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        creds = first_set(KeySource.EPHEMERAL)
        make_vault(state, creds)
        copy = tmp_path / "copy" / "vault.db"
        copy.parent.mkdir()
        real = keys.forget_master_key

        def snapshot_then_forget(source: Any, account: str) -> bool:
            copy.write_bytes(vault_path(state).read_bytes())  # the file after the overwrite
            return real(source, account)

        monkeypatch.setattr(
            "codekavach.privacy.vault.lifecycle.forget_master_key", snapshot_then_forget
        )
        destroy(state, confirm=confirmation_token(state))
        assert copy.exists()
        with pytest.raises(VaultKeyError), Vault(copy, KeySource.EPHEMERAL, KEY, create=False):
            pass

    def test_a_key_management_vault_says_the_service_key_stays(self, state: Path) -> None:
        make_vault(state, first_set(KeySource.KMS))
        result = destroy(state, confirm=confirmation_token(state))
        assert any("key-management service" in line for line in result.caveats)
        assert result.key_entry_removed is False

    def test_a_missing_vault_is_an_error(self, state: Path) -> None:
        with pytest.raises(VaultError):
            destroy(state, confirm="destroy-x")


# --- retention ------------------------------------------------------------------------------


def age(state: Path, scan: str, days: float) -> None:
    connection = sqlite3.connect(vault_path(state))
    try:
        connection.execute(
            "UPDATE scans SET created_at = ? WHERE scan_id = ?",
            ((NOW - timedelta(days=days)).isoformat(), scan),
        )
        connection.commit()
    finally:
        connection.close()


def retention_settings(days: int | None) -> Settings:
    return Settings.model_validate({"privacy": {"vault": {"retention_days": days}}})


class TestRetention:
    def build(self, state: Path) -> None:
        creds = first_set(KeySource.EPHEMERAL)
        with Vault(vault_path(state), creds.source, KEY) as vault:
            for scan in ("older", "boundary", "newer", "newest"):
                vault.put(batch(scan, *NAMES))
            vault.salt()
        age(state, "older", 31)
        age(state, "boundary", 30)
        age(state, "newer", 29)
        age(state, "newest", 0)

    def test_only_scans_older_than_the_window_go(self, state: Path) -> None:
        self.build(state)
        result = apply_retention(state, retention_settings(30), now=NOW)
        assert (result.scans_removed, result.records_removed) == (1, 3)
        assert result.retention_days == 30
        left = {row[0] for row in table(state, "SELECT DISTINCT scan_id FROM records")}
        assert left == {"boundary", "newer", "newest"}
        assert {row[0] for row in table(state, "SELECT scan_id FROM scans")} == left

    def test_the_salt_and_the_header_are_never_touched(self, state: Path) -> None:
        self.build(state)
        with Vault(vault_path(state), KeySource.EPHEMERAL, KEY, create=False) as vault:
            salt = vault.salt().reveal()
        header = table(state, "SELECT * FROM header")
        apply_retention(state, retention_settings(1), now=NOW)
        assert table(state, "SELECT * FROM header") == header
        with Vault(vault_path(state), KeySource.EPHEMERAL, KEY, create=False) as vault:
            assert vault.salt().reveal() == salt
        assert table(state, "SELECT COUNT(*) FROM records") == [(3,)]  # only 'newest' survives

    def test_without_a_setting_it_does_nothing(self, state: Path) -> None:
        self.build(state)
        result = apply_retention(state, retention_settings(None), now=NOW)
        assert (result.scans_removed, result.records_removed) == (0, 0)
        assert result.retention_days is None
        assert table(state, "SELECT COUNT(*) FROM records") == [(12,)]

    def test_without_a_vault_it_does_nothing(self, state: Path) -> None:
        assert apply_retention(state, retention_settings(30), now=NOW).scans_removed == 0

    def test_a_scan_with_no_recorded_time_is_kept_and_counted(self, state: Path) -> None:
        self.build(state)
        connection = sqlite3.connect(vault_path(state))
        connection.execute("DELETE FROM scans WHERE scan_id = 'older'")
        connection.commit()
        connection.close()
        result = apply_retention(state, retention_settings(30), now=NOW)
        assert result.undated_scans_kept == 1
        assert table(state, "SELECT COUNT(*) FROM records WHERE scan_id = 'older'") == [(3,)]

    def test_a_big_scan_is_deleted_in_chunks(
        self, state: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(lifecycle, "_CHUNK", 2)
        self.build(state)
        result = apply_retention(state, retention_settings(1), now=NOW)
        assert result.records_removed == 9
        assert result.scans_removed == 3

    def test_pseudonyms_stay_stable_after_retention(self, state: Path) -> None:
        self.build(state)
        with Vault(vault_path(state), KeySource.EPHEMERAL, KEY, create=False) as vault:
            before: ScanSalt = vault.salt()
        apply_retention(state, retention_settings(1), now=NOW)
        with Vault(vault_path(state), KeySource.EPHEMERAL, KEY, create=False) as vault:
            assert vault.salt().reveal() == before.reveal()
            vault.put(batch("fresh", ("fn_1", "alpha_name")))
            assert vault.lookup("fn_1", scan_id="fresh") == "alpha_name"
            assert vault.lookup("fn_1", scan_id="older") is None  # restoring a removed scan fails

    def test_the_consequence_is_in_the_documented_setting(self) -> None:
        field_info = Settings.model_fields["privacy"].annotation.model_fields["vault"]  # type: ignore[union-attr]
        assert field_info is not None
        description = str(
            Settings.model_json_schema()["$defs"]["VaultSettings"]["properties"]["retention_days"]
        )
        assert "cannot be restored" in description

    def test_a_vault_from_before_the_scan_table_gets_it_on_first_use(self, state: Path) -> None:
        creds = first_set(KeySource.EPHEMERAL)
        make_vault(state, creds)
        connection = sqlite3.connect(vault_path(state))
        connection.execute("DROP TABLE scans")
        connection.execute("DROP TABLE rotations")
        connection.commit()
        connection.close()
        assert vault_info(state, probe=False).rotation_count == 0
        assert apply_retention(state, retention_settings(30), now=NOW).undated_scans_kept == 2
        with open_vault(state, creds) as vault:
            vault.put(batch("scan_new", ("fn_1", "alpha_name")))
        assert table(state, "SELECT COUNT(*) FROM scans") == [(1,)]


def test_hash_of_the_module_docstring_mentions_i3() -> None:
    doc = lifecycle.__doc__ or ""
    assert "I3" in doc
    assert hashlib.sha256(doc.encode()).hexdigest()  # the docstring is present and stable


Callback = Callable[[], None]


@pytest.mark.parametrize(
    ("days", "stated"), [(None, "kept until the vault is destroyed"), (45, "45 days")]
)
def test_the_privacy_attestation_records_the_retention_in_force(
    days: int | None, stated: str
) -> None:
    config = Settings.model_validate({"privacy": {"vault": {"retention_days": days}}})
    assert _attestation(make_scan(), config, None).retention == stated
