"""Performance budgets of the vault lifecycle operations (E10-03).

Status takes under 50 ms; a header-only rotation under 200 ms; a rotation that re-seals the data key
over 50 000 records under 20 s; retention over 50 000 records under 10 s, each transaction under
1 s. The budgets are scaled by the performance factor.
"""

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.vault.info import vault_info
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.lifecycle import apply_retention, rotate_key
from codekavach.privacy.vault.salt import vault_path
from codekavach.privacy.vault.store import Vault
from tests.support.perf import assert_within_budget, measure

KEY = SecretBytes(b"\x44" * 32)
OTHER = SecretBytes(b"\x55" * 32)
STATUS_SECONDS = 0.05
HEADER_ROTATION_SECONDS = 0.2
DATA_ROTATION_SECONDS = 20.0
RETENTION_SECONDS = 10.0
TRANSACTION_SECONDS = 1.0
SCANS = 10
PER_SCAN = 5_000


def fill(state: Path, scans: int = SCANS) -> None:
    with Vault(vault_path(state), KeySource.EPHEMERAL, KEY) as vault:
        for scan in range(scans):
            entries = tuple(
                MappingEntry(f"var_{i + 1}", f"s{scan}_identifier_{i}", PseudonymKind.VAR, "m")
                for i in range(PER_SCAN)
            )
            vault.put(MappingBatch(f"scan_{scan}", entries))


@pytest.mark.perf
def test_status_of_a_large_vault(tmp_path: Path) -> None:
    fill(tmp_path / "state")
    state = tmp_path / "state"

    def status() -> None:
        assert vault_info(state, probe=False).record_count == SCANS * PER_SCAN

    assert_within_budget(measure(status, repeat=5), STATUS_SECONDS, label="vault status")


@pytest.mark.perf
def test_a_header_only_rotation_of_a_small_vault(tmp_path: Path) -> None:
    state = tmp_path / "state"
    fill(state, scans=1)
    keys = [KEY, OTHER]
    turn = {"n": 0}

    def rotate() -> None:
        old, new = keys[turn["n"] % 2], keys[(turn["n"] + 1) % 2]
        turn["n"] += 1
        rotate_key(state, key=old, new_key=new, new_backend="ephemeral")

    assert_within_budget(
        measure(rotate, repeat=3), HEADER_ROTATION_SECONDS, label="header rotation"
    )


@pytest.mark.perf
def test_a_data_key_rotation_over_fifty_thousand_records(tmp_path: Path) -> None:
    state = tmp_path / "state"
    fill(state)
    started = time.perf_counter()
    result = rotate_key(state, key=KEY, new_key=OTHER, new_backend="ephemeral", new_data_key=True)
    assert result.records_reencrypted == SCANS * PER_SCAN
    assert_within_budget(
        time.perf_counter() - started, DATA_ROTATION_SECONDS, label="data-key rotation"
    )


@pytest.mark.perf
def test_retention_over_fifty_thousand_records(tmp_path: Path) -> None:
    state = tmp_path / "state"
    fill(state)
    settings = Settings.model_validate({"privacy": {"vault": {"retention_days": 30}}})
    now = datetime.now(UTC) + timedelta(days=365)
    started = time.perf_counter()
    result = apply_retention(state, settings, now=now)
    elapsed = time.perf_counter() - started
    assert result.records_removed == SCANS * PER_SCAN
    assert_within_budget(elapsed, RETENTION_SECONDS, label="retention")
    assert_within_budget(elapsed, TRANSACTION_SECONDS * SCANS, label="retention transactions")
