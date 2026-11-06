"""The mapping vault (E10-01): envelope encryption, key sources, the store and the salt store."""

import copy
import os
import pickle
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.config import Settings
from codekavach.config.keys import KeyringUnavailableError
from codekavach.core.models.location import Location
from codekavach.core.pipeline.salt import ScanSalt
from codekavach.privacy.pseudonymise.generator import PseudonymGenerator, PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.vault import crypto, keys
from codekavach.privacy.vault.errors import (
    KeySourceUnavailable,
    VaultConsistencyError,
    VaultError,
    VaultFormatError,
    VaultKeyError,
)
from codekavach.privacy.vault.keys import KeySource, ScryptParams, SecretBytes
from codekavach.privacy.vault.salt import get_or_create_salt, vault_path
from codekavach.privacy.vault.store import Vault

KEY = SecretBytes(b"\x11" * 32)
OTHER_KEY = SecretBytes(b"\x22" * 32)
SCAN = "scan_01"
FN = PseudonymKind.FN


def entry(
    pseudonym: str, original: str, scope: str = "mod", where: Location | None = None
) -> MappingEntry:
    kind = PseudonymKind(pseudonym.split("_", maxsplit=1)[0])
    return MappingEntry(pseudonym, original, kind, scope, where)


def batch(*pairs: tuple[str, str], scan: str = SCAN) -> MappingBatch:
    return MappingBatch(scan, tuple(entry(p, o) for p, o in pairs))


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "state" / "vault" / "vault.db"


@pytest.fixture
def vault(db: Path) -> Iterator[Vault]:
    with Vault(db, KeySource.EPHEMERAL, KEY) as opened:
        yield opened


def rows(db: Path, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    connection = sqlite3.connect(db)
    try:
        return connection.execute(sql, args).fetchall()
    finally:
        connection.close()


def execute(db: Path, sql: str, *args: Any) -> None:
    connection = sqlite3.connect(db)
    try:
        connection.execute(sql, args)
        connection.commit()
    finally:
        connection.close()


# --- envelope encryption -------------------------------------------------------------------


class TestEnvelope:
    def test_a_data_key_round_trips_through_its_wrapper(self) -> None:
        data_key = crypto.new_data_key()
        wrapped = crypto.wrap_data_key(KEY.reveal(), data_key)
        assert crypto.unwrap_data_key(KEY.reveal(), wrapped) == data_key
        assert data_key not in wrapped

    def test_a_wrong_master_key_fails_authentication(self) -> None:
        wrapped = crypto.wrap_data_key(KEY.reveal(), crypto.new_data_key())
        with pytest.raises(VaultKeyError):
            crypto.unwrap_data_key(OTHER_KEY.reveal(), wrapped)

    def test_an_altered_wrapper_fails_authentication(self) -> None:
        wrapped = bytearray(crypto.wrap_data_key(KEY.reveal(), crypto.new_data_key()))
        wrapped[-1] ^= 1
        with pytest.raises(VaultKeyError):
            crypto.unwrap_data_key(KEY.reveal(), bytes(wrapped))

    def test_a_record_is_bound_to_its_associated_data(self) -> None:
        cipher = crypto.RecordCipher(crypto.new_data_key())
        nonce = crypto.build_nonce(b"abcd", 1)
        sealed = cipher.seal(nonce, crypto.record_aad("s", "fn_1"), b"secret")
        assert cipher.open(nonce, crypto.record_aad("s", "fn_1"), sealed) == b"secret"
        for other in (crypto.record_aad("s", "fn_2"), crypto.record_aad("t", "fn_1")):
            with pytest.raises(VaultKeyError):
                cipher.open(nonce, other, sealed)

    def test_a_closed_cipher_refuses_work(self) -> None:
        cipher = crypto.RecordCipher(crypto.new_data_key())
        cipher.close()
        with pytest.raises(VaultKeyError):
            cipher.index_hash("x")
        with pytest.raises(VaultKeyError):
            cipher.seal(crypto.build_nonce(b"abcd", 1), b"", b"x")

    def test_nonces_are_a_prefix_and_a_counter(self) -> None:
        assert crypto.build_nonce(b"abcd", 1) == b"abcd" + (1).to_bytes(8, "big")
        assert len({crypto.build_nonce(b"abcd", n) for n in range(1, 500)}) == 499
        for bad in (0, crypto.COUNTER_LIMIT + 1):
            with pytest.raises(VaultKeyError):
                crypto.build_nonce(b"abcd", bad)

    def test_the_index_depends_on_the_key_and_is_16_bytes(self) -> None:
        one = crypto.RecordCipher(b"\x01" * 32)
        two = crypto.RecordCipher(b"\x02" * 32)
        assert len(one.index_hash("name")) == crypto.INDEX_BYTES
        assert one.index_hash("name") == one.index_hash("name")
        assert one.index_hash("name") != two.index_hash("name")
        assert one.index_hash("name") != one.index_hash("other")


# --- key sources ---------------------------------------------------------------------------


class TestKeySources:
    def test_the_ephemeral_source_gives_a_stable_key_under_pytest(self) -> None:
        first = keys.resolve_master_key(KeySource.EPHEMERAL, settings=None, account="a")
        again = keys.resolve_master_key("ephemeral", settings=None, account="a")
        other = keys.resolve_master_key(KeySource.EPHEMERAL, settings=None, account="b")
        assert first.reveal() == again.reveal() != other.reveal()

    def test_the_ephemeral_source_refuses_to_run_outside_pytest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delitem(sys.modules, "pytest")
        with pytest.raises(KeySourceUnavailable, match="tests only"):
            keys.resolve_master_key(KeySource.EPHEMERAL, settings=None)

    def test_the_kms_source_names_its_issue(self) -> None:
        with pytest.raises(KeySourceUnavailable, match="E10-03"):
            keys.resolve_master_key(KeySource.KMS, settings=None)

    def test_an_unknown_source_is_refused(self) -> None:
        with pytest.raises(KeySourceUnavailable):
            keys.resolve_master_key("somewhere", settings=None)

    def test_the_keyring_source_creates_then_reuses_its_entry(self, memory_keyring: Any) -> None:
        first = keys.resolve_master_key(KeySource.KEYRING, settings=None, account="vault-1")
        again = keys.resolve_master_key(KeySource.KEYRING, settings=None, account="vault-1")
        assert first.reveal() == again.reveal()
        assert list(memory_keyring.store) == [(keys.KEYRING_SERVICE, "vault-1")]

    def test_the_keyring_source_does_not_invent_a_key_when_told_not_to(
        self, memory_keyring: Any
    ) -> None:
        with pytest.raises(KeySourceUnavailable, match="no key"):
            keys.resolve_master_key(KeySource.KEYRING, settings=None, account="x", create=False)
        assert memory_keyring.store == {}

    def test_a_keyring_entry_that_is_not_a_key_is_refused(self, memory_keyring: Any) -> None:
        memory_keyring.store[(keys.KEYRING_SERVICE, "bad")] = "not hex"
        with pytest.raises(KeySourceUnavailable, match="not a vault key"):
            keys.resolve_master_key(KeySource.KEYRING, settings=None, account="bad")

    def test_a_missing_keyring_is_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def broken(ref: str = "keyring") -> Any:
            raise KeyringUnavailableError

        monkeypatch.setattr(keys, "open_keyring", broken)
        with pytest.raises(KeySourceUnavailable, match="keyring"):
            keys.resolve_master_key(KeySource.KEYRING, settings=None)

    def test_the_passphrase_source_needs_a_passphrase_and_parameters(self) -> None:
        params = ScryptParams(salt=b"s" * 16, n=2**10)
        with pytest.raises(KeySourceUnavailable):
            keys.resolve_master_key(
                KeySource.PASSPHRASE, settings=None, kdf=None, prompt=lambda: "x"
            )
        with pytest.raises(KeySourceUnavailable):
            keys.resolve_master_key(KeySource.PASSPHRASE, settings=None, kdf=params)
        with pytest.raises(KeySourceUnavailable):
            keys.resolve_master_key(
                KeySource.PASSPHRASE, settings=None, kdf=params, prompt=lambda: ""
            )

    def test_the_passphrase_key_depends_on_passphrase_salt_and_cost(self) -> None:
        base = ScryptParams(salt=b"s" * 16, n=2**10)
        a = keys.derive_passphrase_key("one", base).reveal()
        assert a == keys.derive_passphrase_key("one", base).reveal()
        assert a != keys.derive_passphrase_key("two", base).reveal()
        assert (
            a != keys.derive_passphrase_key("one", ScryptParams(salt=b"t" * 16, n=2**10)).reveal()
        )
        assert (
            a != keys.derive_passphrase_key("one", ScryptParams(salt=b"s" * 16, n=2**11)).reveal()
        )

    def test_the_passphrase_can_come_from_a_secret_reference(self) -> None:
        configured = Settings.model_validate(
            {"privacy": {"vault": {"key_source": "passphrase", "passphrase": "env:CK_TEST_PASS"}}}
        )
        params = ScryptParams(salt=b"s" * 16, n=2**10)
        got = keys.resolve_master_key(
            KeySource.PASSPHRASE, settings=configured, kdf=params, env={"CK_TEST_PASS": "pw"}
        )
        assert got.reveal() == keys.derive_passphrase_key("pw", params).reveal()
        with pytest.raises(KeySourceUnavailable, match="passphrase"):
            keys.resolve_master_key(KeySource.PASSPHRASE, settings=configured, kdf=params, env={})

    @pytest.mark.parametrize(
        "data",
        [
            {"kdf": "scrypt", "n": 2**30, "r": 8, "p": 1, "salt": "00" * 16},
            {"kdf": "scrypt", "n": 3, "r": 8, "p": 1, "salt": "00" * 16},
            {"kdf": "scrypt", "n": 2**15, "r": 0, "p": 1, "salt": "00" * 16},
            {"kdf": "scrypt", "n": 2**15, "r": 8, "p": 1, "salt": "00"},
            {"kdf": "argon", "n": 2**15, "r": 8, "p": 1, "salt": "00" * 16},
            {"kdf": "scrypt"},
            "text",
        ],
    )
    def test_a_header_cannot_ask_for_absurd_derivation_costs(self, data: object) -> None:
        with pytest.raises(VaultFormatError):
            ScryptParams.from_json(data)

    def test_secret_bytes_hide_and_refuse_copies(self) -> None:
        assert "11" not in repr(KEY) + str(KEY) + f"{KEY}" + f"{KEY}"
        for attempt in (pickle.dumps, copy.copy, copy.deepcopy):
            with pytest.raises(TypeError):
                attempt(KEY)
        with pytest.raises(AttributeError):
            KEY.other = 1
        with pytest.raises(ValueError):
            SecretBytes(b"short")


# --- the store -----------------------------------------------------------------------------


class TestStore:
    def test_a_stored_mapping_comes_back(self, vault: Vault) -> None:
        where = Location(path="src/pay.py", start_line=3, end_line=9, symbol="accrue")
        vault.put(MappingBatch(SCAN, (entry("fn_1", "accrue_premium_interest", "pay", where),)))
        assert vault.lookup("fn_1") == "accrue_premium_interest"
        assert vault.reverse("accrue_premium_interest") == "fn_1"
        record = vault.get_record("fn_1")
        assert record is not None
        assert (record.original, record.kind, record.scope) == (
            "accrue_premium_interest",
            FN,
            "pay",
        )
        assert record.first_location == where

    def test_unknown_names_return_none(self, vault: Vault) -> None:
        assert vault.lookup("fn_9") is None
        assert vault.reverse("nothing") is None
        assert vault.get_record("fn_9") is None

    def test_the_file_never_holds_an_original_or_the_key(self, vault: Vault, db: Path) -> None:
        vault.put(batch(("fn_1", "accrue_premium_interest"), ("var_1", "customer_balance")))
        vault.close()
        blob = db.read_bytes()
        wal = db.with_name(db.name + "-wal")
        blob += wal.read_bytes() if wal.exists() else b""
        for secret in (b"accrue_premium_interest", b"customer_balance", KEY.reveal()):
            assert secret not in blob

    def test_put_is_idempotent(self, vault: Vault, db: Path) -> None:
        pairs = batch(("fn_1", "alpha_name"), ("fn_2", "bravo_name"))
        vault.put(pairs)
        before = rows(db, "SELECT id, nonce, ciphertext FROM records ORDER BY id")
        vault.put(pairs)
        assert rows(db, "SELECT id, nonce, ciphertext FROM records ORDER BY id") == before

    def test_a_conflicting_original_raises_and_rolls_back_the_batch(
        self, vault: Vault, db: Path
    ) -> None:
        vault.put(batch(("fn_1", "alpha_name")))
        with pytest.raises(VaultConsistencyError) as caught:
            vault.put(batch(("fn_2", "bravo_name"), ("fn_1", "other_name")))
        assert "other_name" not in str(caught.value) + repr(caught.value)
        assert rows(db, "SELECT pseudonym FROM records") == [("fn_1",)]
        assert vault.lookup("fn_1") == "alpha_name"

    def test_a_conflict_inside_one_batch_is_caught(self, vault: Vault) -> None:
        with pytest.raises(VaultConsistencyError):
            vault.put(batch(("fn_1", "alpha_name"), ("fn_1", "bravo_name")))
        assert vault.original_count(0) == 0

    def test_the_same_pseudonym_may_differ_between_scans(self, vault: Vault) -> None:
        vault.put(batch(("fn_1", "alpha_name"), scan="s1"))
        vault.put(batch(("fn_1", "bravo_name"), scan="s2"))
        assert vault.lookup("fn_1", scan_id="s1") == "alpha_name"
        assert vault.lookup("fn_1", scan_id="s2") == "bravo_name"
        assert vault.lookup("fn_1") == "bravo_name"
        assert vault.reverse("alpha_name", scan_id="s2") is None
        assert vault.reverse("alpha_name", scan_id="s1") == "fn_1"

    def test_the_same_pair_in_a_second_scan_is_a_second_record(self, vault: Vault) -> None:
        vault.put(batch(("fn_1", "alpha_name"), scan="s1"))
        vault.put(batch(("fn_1", "alpha_name"), scan="s2"))
        assert vault.lookup("fn_1", scan_id="s2") == "alpha_name"
        assert list(vault.iter_originals()) == ["alpha_name"]

    @pytest.mark.parametrize(
        "bad",
        [
            MappingBatch("", (entry("fn_1", "alpha_name"),)),
            MappingBatch(SCAN, (entry("fn_1", ""),)),
            MappingBatch(SCAN, (MappingEntry("Account", "alpha_name", FN, "m"),)),
        ],
    )
    def test_malformed_batches_are_refused(self, vault: Vault, bad: MappingBatch) -> None:
        with pytest.raises(VaultError):
            vault.put(bad)

    def test_an_empty_batch_does_nothing(self, vault: Vault) -> None:
        vault.put(MappingBatch(SCAN))
        assert vault.original_count(0) == 0

    def test_originals_respect_the_minimum_length_and_are_distinct(self, vault: Vault) -> None:
        vault.put(batch(("var_1", "abc"), ("var_2", "abcd"), ("var_3", "abcde")))
        vault.put(batch(("var_1", "abc"), ("var_2", "abcd"), scan="s2"))
        assert sorted(vault.iter_originals()) == ["abcd", "abcde"]
        assert sorted(vault.iter_originals(min_len=5)) == ["abcde"]
        assert sorted(vault.iter_originals(min_len=0)) == ["abc", "abcd", "abcde"]
        assert vault.original_count() == 2
        assert vault.original_count(5) == 1
        assert vault.original_count(0) == 3
        with pytest.raises(ValueError):
            list(vault.iter_originals(min_len=-1))

    def test_iter_originals_is_lazy(self, vault: Vault) -> None:
        vault.put(batch(("var_1", "abcd")))
        iterator = vault.iter_originals()
        assert iter(iterator) is iterator
        assert next(iterator) == "abcd"

    def test_original_count_decrypts_nothing(
        self, vault: Vault, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        vault.put(batch(("var_1", "abcd"), ("var_2", "efghi")))
        calls: list[int] = []
        real = crypto.RecordCipher.open

        def counting(self: crypto.RecordCipher, *args: Any) -> bytes:
            calls.append(1)
            return real(self, *args)

        monkeypatch.setattr(crypto.RecordCipher, "open", counting)
        assert vault.original_count() == 2
        assert calls == []
        assert sorted(vault.iter_originals()) == ["abcd", "efghi"]
        assert len(calls) == 2

    def test_a_moved_ciphertext_fails_to_decrypt(self, vault: Vault, db: Path) -> None:
        vault.put(batch(("fn_1", "alpha_name"), ("fn_2", "bravo_name")))
        (one,) = rows(db, "SELECT nonce, ciphertext FROM records WHERE pseudonym = 'fn_1'")
        execute(db, "UPDATE records SET nonce = ?, ciphertext = ? WHERE pseudonym = 'fn_2'", *one)
        assert vault.lookup("fn_1") == "alpha_name"
        with pytest.raises(VaultKeyError):
            vault.lookup("fn_2")

    def test_a_ciphertext_moved_to_another_scan_fails(self, vault: Vault, db: Path) -> None:
        vault.put(batch(("fn_1", "alpha_name"), scan="s1"))
        vault.put(batch(("fn_1", "bravo_name"), scan="s2"))
        (one,) = rows(db, "SELECT nonce, ciphertext FROM records WHERE scan_id = 's1'")
        execute(db, "UPDATE records SET nonce = ?, ciphertext = ? WHERE scan_id = 's2'", *one)
        with pytest.raises(VaultKeyError):
            vault.lookup("fn_1", scan_id="s2")

    def test_a_flipped_bit_in_a_record_fails(self, vault: Vault, db: Path) -> None:
        vault.put(batch(("fn_1", "alpha_name")))
        (stored,) = rows(db, "SELECT ciphertext FROM records")
        damaged = bytearray(stored[0])
        damaged[0] ^= 1
        execute(db, "UPDATE records SET ciphertext = ?", bytes(damaged))
        with pytest.raises(VaultKeyError):
            vault.lookup("fn_1")

    def test_nonces_are_unique_and_counted(self, vault: Vault, db: Path) -> None:
        for number in range(5):
            vault.put(
                batch(
                    (f"var_{number * 2 + 1}", f"name_{number}a"),
                    (f"var_{number * 2 + 2}", f"name_{number}b"),
                    scan=f"s{number}",
                )
            )
        vault.salt()
        nonces = [row[0] for row in rows(db, "SELECT nonce FROM records")]
        (salt_nonce,) = rows(db, "SELECT salt_nonce FROM header")[0]
        (counter,) = rows(db, "SELECT nonce_counter FROM header")[0]
        assert len({*nonces, salt_nonce}) == len(nonces) + 1 == counter
        assert {nonce[:4] for nonce in nonces} == {salt_nonce[:4]}

    def test_a_counter_that_went_backwards_is_refused(self, vault: Vault, db: Path) -> None:
        vault.put(batch(("fn_1", "alpha_name"), ("fn_2", "bravo_name")))
        execute(db, "UPDATE header SET nonce_counter = 0")
        with pytest.raises(VaultFormatError, match="nonce counter"):
            vault.put(batch(("fn_3", "charlie_name")))

    def test_closing_the_vault_stops_it(self, db: Path) -> None:
        opened = Vault(db, KeySource.EPHEMERAL, KEY)
        opened.put(batch(("fn_1", "alpha_name")))
        opened.close()
        with pytest.raises(VaultKeyError):
            opened.lookup("fn_1")
        with pytest.raises(VaultKeyError):
            opened.put(batch(("fn_2", "bravo_name")))


class TestFiles:
    @pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
    def test_the_file_is_private_in_a_private_directory(self, vault: Vault, db: Path) -> None:
        vault.put(batch(("fn_1", "alpha_name")))
        assert db.stat().st_mode & 0o777 == 0o600
        assert db.parent.stat().st_mode & 0o777 == 0o700
        for sidecar in db.parent.iterdir():
            assert sidecar.stat().st_mode & 0o077 == 0

    def test_a_wrong_master_key_does_not_open_a_vault(self, db: Path) -> None:
        Vault(db, KeySource.EPHEMERAL, KEY).close()
        with pytest.raises(VaultKeyError):
            Vault(db, KeySource.EPHEMERAL, OTHER_KEY)

    def test_a_vault_reopens_with_its_key(self, db: Path) -> None:
        with Vault(db, KeySource.EPHEMERAL, KEY) as first:
            first.put(batch(("fn_1", "alpha_name")))
        with Vault(db, KeySource.EPHEMERAL, KEY, create=False) as second:
            assert second.lookup("fn_1") == "alpha_name"

    def test_a_missing_vault_is_not_created_when_told_not_to(self, db: Path) -> None:
        with pytest.raises(VaultError, match="no vault"):
            Vault(db, KeySource.EPHEMERAL, KEY, create=False)
        assert not db.exists()

    def test_a_file_that_is_not_a_vault_is_refused(self, db: Path) -> None:
        db.parent.mkdir(parents=True)
        db.write_bytes(b"this is not a database at all, " * 20)
        with pytest.raises(VaultFormatError):
            Vault(db, KeySource.EPHEMERAL, KEY)

    def test_an_unknown_format_version_is_refused(self, db: Path) -> None:
        Vault(db, KeySource.EPHEMERAL, KEY).close()
        execute(db, "UPDATE header SET format_version = 99")
        with pytest.raises(VaultFormatError, match="format"):
            Vault(db, KeySource.EPHEMERAL, KEY)

    def test_an_unknown_key_source_is_refused(self, db: Path) -> None:
        with pytest.raises(VaultError):
            Vault(db, "somewhere", KEY)

    def test_the_keyring_vault_is_unreadable_without_its_entry(
        self, db: Path, memory_keyring: Any
    ) -> None:
        with Vault(db, KeySource.KEYRING) as first:
            first.put(batch(("fn_1", "alpha_name")))
        (account,) = [name for _, name in memory_keyring.store]
        assert account.startswith("vault-")
        memory_keyring.store[(keys.KEYRING_SERVICE, account)] = "ab" * 32
        with pytest.raises(VaultKeyError):
            Vault(db, KeySource.KEYRING)
        del memory_keyring.store[(keys.KEYRING_SERVICE, account)]
        with pytest.raises(KeySourceUnavailable):
            Vault(db, KeySource.KEYRING)

    def test_a_vault_cannot_be_opened_under_another_key_source(
        self, db: Path, memory_keyring: Any
    ) -> None:
        Vault(db, KeySource.KEYRING).close()
        with pytest.raises(VaultKeyError, match="keyring"):
            Vault(db, KeySource.PASSPHRASE, prompt=lambda: "pw")

    def test_a_passphrase_vault_opens_only_with_the_passphrase(self, db: Path) -> None:
        with Vault(db, KeySource.PASSPHRASE, prompt=lambda: "correct horse") as first:
            first.put(batch(("fn_1", "alpha_name")))
        with Vault(db, KeySource.PASSPHRASE, prompt=lambda: "correct horse") as again:
            assert again.lookup("fn_1") == "alpha_name"
        with pytest.raises(VaultKeyError):
            Vault(db, KeySource.PASSPHRASE, prompt=lambda: "wrong")
        with pytest.raises(KeySourceUnavailable):
            Vault(db, KeySource.PASSPHRASE)
        assert b"correct horse" not in db.read_bytes()

    def test_a_vault_made_under_old_scrypt_costs_still_opens(
        self, db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        old = ScryptParams(salt=b"o" * 16, n=2**10, r=4, p=1)
        monkeypatch.setattr(ScryptParams, "fresh", classmethod(lambda cls: old))
        with Vault(db, KeySource.PASSPHRASE, prompt=lambda: "pw") as first:
            first.put(batch(("fn_1", "alpha_name")))
        monkeypatch.undo()
        assert ScryptParams.fresh().n == keys.DEFAULT_SCRYPT_N != old.n
        recorded = rows(db, "SELECT kdf FROM header")[0][0]
        assert '"n": 1024' in recorded and '"r": 4' in recorded
        with Vault(db, KeySource.PASSPHRASE, prompt=lambda: "pw") as again:
            assert again.lookup("fn_1") == "alpha_name"

    def test_the_default_scrypt_cost_is_documented_and_current(self) -> None:
        params = ScryptParams.fresh()
        assert (params.n, params.r, params.p) == (2**15, 8, 1)
        assert len(params.salt) == keys.SCRYPT_SALT_BYTES


# --- the salt store ------------------------------------------------------------------------


@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "state"


class TestSalt:
    def test_the_project_salt_is_stable_across_scans_and_opens(self, state: Path) -> None:
        with_settings = Settings.model_validate({})
        first = _salt(state, with_settings, "scan_a")
        second = _salt(state, with_settings, "scan_b")
        assert isinstance(first, ScanSalt)
        assert first == second
        assert len(first.reveal()) == 32

    def test_the_scan_salt_differs_by_scan_and_from_the_project_salt(self, state: Path) -> None:
        configured = Settings.model_validate({})
        project = _salt(state, configured, "scan_a")
        one = _salt(state, configured, "scan_a", mode="scan")
        two = _salt(state, configured, "scan_b", mode="scan")
        assert len({project, one, two}) == 3
        assert one == _salt(state, configured, "scan_a", mode="scan")

    def test_a_salt_made_while_we_waited_is_kept(
        self, db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two writers both find no salt; the second must adopt the first one's, not replace it."""
        with (
            Vault(db, KeySource.EPHEMERAL, KEY) as first,
            Vault(db, KeySource.EPHEMERAL, KEY) as second,
        ):
            real = Vault._salt_row
            calls: list[int] = []

            def stale_first_read(connection: sqlite3.Connection) -> Any:
                calls.append(1)
                return None if len(calls) == 1 else real(connection)

            made = first.salt()
            monkeypatch.setattr(Vault, "_salt_row", staticmethod(stale_first_read))
            assert second.salt() == made
            assert first.salt() == made

    def test_another_project_gets_another_salt(self, state: Path, tmp_path: Path) -> None:
        configured = Settings.model_validate({})
        assert _salt(state, configured, "s") != _salt(tmp_path / "other", configured, "s")

    def test_an_unknown_mode_is_refused(self, state: Path) -> None:
        with pytest.raises(ValueError, match="mode"):
            _salt(state, Settings.model_validate({}), "s", mode="request")

    def test_the_salt_is_sealed_in_the_file_and_never_in_the_clear(self, state: Path) -> None:
        configured = Settings.model_validate({})
        salt = _salt(state, configured, "s")
        path = vault_path(state)
        data = path.read_bytes()
        wal = path.with_name(path.name + "-wal")
        data += wal.read_bytes() if wal.exists() else b""
        assert salt.reveal() not in data
        assert repr(salt) == "ScanSalt(<redacted>)"

    def test_a_tampered_salt_fails_to_open(self, state: Path) -> None:
        configured = Settings.model_validate({})
        _salt(state, configured, "s")
        execute(vault_path(state), "UPDATE header SET salt_ciphertext = zeroblob(48)")
        with pytest.raises(VaultKeyError):
            _salt(state, configured, "s")

    def test_the_salt_uses_the_configured_key_source(self, state: Path) -> None:
        configured = Settings.model_validate(
            {"privacy": {"vault": {"key_source": "passphrase", "passphrase": "env:CK_PW"}}}
        )
        env = {"CK_PW": "pw"}
        first = get_or_create_salt(state, configured, scan_id="s", env=env)
        assert get_or_create_salt(state, configured, scan_id="s", env=env) == first
        with pytest.raises(KeySourceUnavailable):
            get_or_create_salt(state, configured, scan_id="s", env={})

    def test_the_salt_of_a_scan_feeds_the_generator(self, state: Path) -> None:
        configured = Settings.model_validate({})
        pseudonyms = []
        for scan in ("scan_a", "scan_b"):
            generator = PseudonymGenerator(_salt(state, configured, scan))
            generator.prepare(FN, ["alpha", "bravo", "charlie"])
            pseudonyms.append({n: generator.token(FN, n) for n in ("alpha", "bravo", "charlie")})
        assert pseudonyms[0] == pseudonyms[1]


def _salt(state: Path, configured: Settings, scan: str, **kwargs: Any) -> ScanSalt:
    return get_or_create_salt(state, configured, scan_id=scan, key=KEY, **kwargs)


# --- properties ----------------------------------------------------------------------------

names = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_0123456789", min_size=1, max_size=14)


@settings(
    max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    originals=st.lists(names, min_size=1, max_size=15, unique=True),
    min_len=st.integers(0, 8),
    seed=st.randoms(),
)
def test_stored_pairs_round_trip_and_the_set_ignores_insertion_order(
    tmp_path_factory: pytest.TempPathFactory, originals: list[str], min_len: int, seed: Any
) -> None:
    numbered = [(f"var_{index + 1}", original) for index, original in enumerate(originals)]
    shuffled = list(numbered)
    seed.shuffle(shuffled)
    root = tmp_path_factory.mktemp("prop")
    with (
        Vault(root / "a.db", KeySource.EPHEMERAL, KEY) as first,
        Vault(root / "b.db", KeySource.EPHEMERAL, KEY) as second,
    ):
        first.put(batch(*numbered))
        second.put(batch(*shuffled))
        for pseudonym, original in numbered:
            assert first.lookup(pseudonym) == original
            assert first.reverse(original) == pseudonym
        expected = {original for original in originals if len(original) >= min_len}
        assert set(first.iter_originals(min_len=min_len)) == expected
        assert set(second.iter_originals(min_len=min_len)) == expected
        assert first.original_count(min_len) == len(expected) == second.original_count(min_len)
        assert list(first.iter_originals(min_len=min_len)).count("") == 0
