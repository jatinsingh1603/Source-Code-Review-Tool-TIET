"""I3, vault locality: nothing the vault holds leaves it through a log, a message or a schema.

The vault keeps the mapping that undoes everything the privacy layer did, so these tests look for
the original, the master key and the salt in every channel a careless change could use: log
events, exception text, ``repr``/``str``/format output, artefact schemas and the stores' refusal of
unpersistable values. The import half of the guard (nothing outside the vault and the restore
engine imports ``MappingRecord``) is the ``vault-record-locality`` contract in
``test_import_contracts.py``.
"""

import contextlib
import importlib
import inspect
import json
import logging
import pkgutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel
from structlog.testing import capture_logs

from codekavach.config import Settings
from codekavach.core.models.location import Location
from codekavach.core.store.base import check_never_persist
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.vault import crypto
from codekavach.privacy.vault.errors import (
    KeySourceUnavailable,
    VaultConsistencyError,
    VaultError,
    VaultFormatError,
    VaultKeyError,
)
from codekavach.privacy.vault.keys import KeySource, ScryptParams, SecretBytes, resolve_master_key
from codekavach.privacy.vault.models import MappingRecord
from codekavach.privacy.vault.salt import get_or_create_salt
from codekavach.privacy.vault.store import Vault

pytestmark = pytest.mark.privacy

REPO = Path(__file__).resolve().parents[2]
KEY = SecretBytes(b"\x5c" * 32)
ORIGINALS = ("zq_accrue_premium_interest", "zq_customer_balance_total", "zq_internal_ledger")
WHERE = Location(path="src/zq_secret_module.py", start_line=2, end_line=4, symbol="zq_where")
SCAN = "scan_i3"


def leaks() -> tuple[str, ...]:
    """Every string that must stay out of logs, messages and schemas."""
    return (*ORIGINALS, "zq_secret_module", "zq_where", KEY.reveal().hex(), "5c5c5c5c")


def batch(scan: str = SCAN) -> MappingBatch:
    return MappingBatch(
        scan,
        tuple(
            MappingEntry(f"var_{index}", original, PseudonymKind.VAR, "zq_scope", WHERE)
            for index, original in enumerate(ORIGINALS, start=1)
        ),
    )


def assert_clean(text: str) -> None:
    for secret in leaks():
        assert secret not in text, "a vault value reached an output channel"


@pytest.fixture
def vault(tmp_path: Path) -> Vault:
    return Vault(tmp_path / "vault" / "vault.db", KeySource.EPHEMERAL, KEY)


def exercise(vault: Vault, tmp_path: Path) -> dict[str, Callable[[], object]]:
    """One call for every public method of ``Vault``; the test below checks none is missing."""
    return {
        "put": lambda: vault.put(batch()),
        "get_record": lambda: vault.get_record("var_1"),
        "lookup": lambda: vault.lookup("var_1"),
        "reverse": lambda: vault.reverse(ORIGINALS[0]),
        "iter_originals": lambda: list(vault.iter_originals(min_len=1)),
        "original_count": lambda: vault.original_count(1),
        "salt": vault.salt,
        "close": lambda: None,  # closed last, below
        "path": lambda: vault.path,
    }


def test_the_exercise_covers_every_public_method(vault: Vault, tmp_path: Path) -> None:
    public = {
        name
        for name, member in inspect.getmembers(Vault)
        if not name.startswith("_") and (callable(member) or isinstance(member, property))
    }
    assert public == set(exercise(vault, tmp_path))


def test_no_log_line_holds_a_vault_value(
    vault: Vault, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with capture_logs() as events:
        for call in exercise(vault, tmp_path).values():
            call()
        vault.close()
        for attempt in (
            lambda: Vault(
                tmp_path / "vault" / "vault.db", KeySource.EPHEMERAL, SecretBytes(b"\x01" * 32)
            ),
            lambda: get_or_create_salt(
                tmp_path / "other", Settings.model_validate({}), scan_id=SCAN, key=KEY
            ),
        ):
            with contextlib.suppress(VaultError):
                attempt()
    assert events, "the vault should log that it was opened and written"
    assert_clean(json.dumps(events, default=repr))
    assert_clean(caplog.text)


def test_the_logs_name_counts_and_scans_only(vault: Vault) -> None:
    with capture_logs() as events:
        vault.put(batch())
    assert [event["event"] for event in events] == ["vault_put"]
    assert set(events[0]) <= {"event", "log_level", "scan_id", "added", "unchanged"}


def failures(tmp_path: Path) -> list[Callable[[], object]]:
    first = Vault(tmp_path / "f" / "vault.db", KeySource.EPHEMERAL, KEY)
    first.put(batch())

    def conflict() -> None:
        other = MappingBatch(SCAN, (MappingEntry("var_1", ORIGINALS[2], PseudonymKind.VAR, "s"),))
        first.put(other)

    def wrong_key() -> None:
        Vault(tmp_path / "f" / "vault.db", KeySource.EPHEMERAL, SecretBytes(b"\x07" * 32))

    def malformed() -> None:
        first.put(MappingBatch(SCAN, (MappingEntry("Name", ORIGINALS[0], PseudonymKind.VAR, "s"),)))

    def closed() -> None:
        second = Vault(tmp_path / "f" / "vault.db", KeySource.EPHEMERAL, KEY)
        second.close()
        second.lookup("var_1")

    def not_a_vault() -> None:
        path = tmp_path / "g" / "x.db"
        path.parent.mkdir()
        path.write_bytes(ORIGINALS[0].encode() * 20)
        Vault(path, KeySource.EPHEMERAL, KEY)

    def bad_params() -> None:
        ScryptParams.from_json({"kdf": "scrypt", "n": 3, "salt": KEY.reveal().hex()})

    def kms() -> None:
        resolve_master_key(KeySource.KMS, settings=None)

    return [conflict, wrong_key, malformed, closed, not_a_vault, bad_params, kms]


def test_no_exception_message_holds_a_vault_value(tmp_path: Path) -> None:
    raised = []
    for call in failures(tmp_path):
        with pytest.raises(
            (
                VaultConsistencyError,
                VaultKeyError,
                VaultFormatError,
                KeySourceUnavailable,
                VaultError,
            )
        ) as caught:
            call()
        raised.append(caught.value)
        assert_clean(str(caught.value) + repr(caught.value) + repr(caught.value.args))
    assert len(raised) == len(failures(tmp_path))


def test_no_repr_shows_a_vault_value(vault: Vault) -> None:
    vault.put(batch())
    record = vault.get_record("var_1")
    assert record is not None and record.original == ORIGINALS[0]
    shown = [
        repr(record),
        str(record),
        f"{record}",
        repr(vault),
        str(vault),
        f"{vault!r}",
        repr(KEY),
        str(KEY),
        f"{KEY}",
        repr(crypto.RecordCipher(b"\x5c" * 32)),
        repr(vault.salt()),
        repr(batch()),
        repr(batch().entries[0]),
    ]
    for text in shown:
        assert_clean(text)
        assert "5c5c" not in text
    assert repr(record) == "MappingRecord(var_1, var)"


def test_the_vault_types_are_never_persisted(vault: Vault) -> None:
    record = vault.get_record("var_1") or MappingRecord(
        "var_1", ORIGINALS[0], PseudonymKind.VAR, "s"
    )
    for value in (record, KEY, batch(), batch().entries[0], vault.salt()):
        with pytest.raises(Exception, match="never"):
            check_never_persist(value)


def model_classes() -> list[type[BaseModel]]:
    found: dict[str, type[BaseModel]] = {}
    for package in ("codekavach.core.models", "codekavach.config.models", "codekavach.privacy"):
        root = importlib.import_module(package)
        modules = [root] + [
            importlib.import_module(info.name)
            for info in pkgutil.walk_packages(root.__path__, f"{package}.")
            if ".vault" not in info.name
        ]
        for module in modules:
            for _, member in inspect.getmembers(module, inspect.isclass):
                if issubclass(member, BaseModel) and member.__module__.startswith("codekavach"):
                    found[f"{member.__module__}.{member.__qualname__}"] = member
    return list(found.values())


def test_no_model_has_a_vault_type_in_a_field() -> None:
    models = model_classes()
    assert len(models) > 30, "the walk should find the real models"
    forbidden = ("MappingRecord", "SecretBytes", "RecordCipher", "privacy.vault")
    for model in models:
        for name, field in model.model_fields.items():
            annotation = repr(field.annotation)
            assert not any(word in annotation for word in forbidden), (model.__name__, name)


def test_no_published_schema_mentions_the_vault_records() -> None:
    schemas = sorted((REPO / "docs" / "schemas").glob("*.schema.json"))
    assert len(schemas) >= 10
    for path in schemas:
        text = path.read_text(encoding="utf-8")
        for word in ("MappingRecord", "SecretBytes", "original_index", "wrapped_key", "ciphertext"):
            assert word not in text, (path.name, word)


def test_the_vault_records_are_not_models() -> None:
    for kind in (MappingRecord, MappingEntry, MappingBatch, SecretBytes):
        assert not issubclass(kind, BaseModel)
        assert not hasattr(kind, "model_dump")


def test_a_dump_shows_no_original_in_the_file_or_the_directory(tmp_path: Path) -> None:
    state = tmp_path / "state"
    get_or_create_salt(state, Settings.model_validate({}), scan_id=SCAN, key=KEY)
    with Vault(state / "vault" / "vault.db", KeySource.EPHEMERAL, KEY) as opened:
        opened.put(batch())
    blobs: Any = [path.read_bytes() for path in state.rglob("*") if path.is_file()]
    assert blobs
    for blob in blobs:
        for secret in leaks():
            assert secret.encode() not in blob
