"""Performance budgets of the mapping vault (E10-01).

Opening a vault under a passphrase (scrypt at the default cost) and unwrapping its data key takes
under 400 ms; inserting a batch of 500 mappings under 100 ms; streaming 50 000 originals for the
egress guard's automaton under 2 s. The budgets are scaled by the performance factor.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest

from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault
from tests.support.perf import assert_within_budget, measure

KEY = SecretBytes(b"\x44" * 32)
OPEN_BUDGET_SECONDS = 0.4
INSERT_BUDGET_SECONDS = 0.1
ITERATE_BUDGET_SECONDS = 2.0
BATCH_SIZE = 500
TOTAL = 50_000


def entries(prefix: str, count: int) -> tuple[MappingEntry, ...]:
    return tuple(
        MappingEntry(f"var_{index + 1}", f"{prefix}_identifier_{index}", PseudonymKind.VAR, "m")
        for index in range(count)
    )


@pytest.fixture(scope="module")
def big_vault(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Vault]:
    path = tmp_path_factory.mktemp("big") / "vault.db"
    with Vault(path, KeySource.EPHEMERAL, KEY) as vault:
        for scan in range(TOTAL // 5_000):
            vault.put(MappingBatch(f"scan_{scan}", entries(f"s{scan}", 5_000)))
        yield vault


@pytest.mark.perf
def test_opening_a_passphrase_vault_stays_within_budget(tmp_path: Path) -> None:
    path = tmp_path / "vault.db"
    Vault(path, KeySource.PASSPHRASE, prompt=lambda: "a passphrase").close()

    def reopen() -> None:
        Vault(path, KeySource.PASSPHRASE, prompt=lambda: "a passphrase").close()

    assert_within_budget(measure(reopen, repeat=3), OPEN_BUDGET_SECONDS, label="open")


@pytest.mark.perf
def test_inserting_500_mappings_stays_within_budget(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.db", KeySource.EPHEMERAL, KEY)
    counter = iter(range(1_000_000))

    def insert() -> None:
        vault.put(MappingBatch(f"scan_{next(counter)}", entries("p", BATCH_SIZE)))

    assert_within_budget(measure(insert, repeat=5), INSERT_BUDGET_SECONDS, label="insert 500")
    vault.close()


@pytest.mark.perf
def test_streaming_50000_originals_stays_within_budget(big_vault: Vault) -> None:
    def stream() -> None:
        assert sum(1 for _ in big_vault.iter_originals()) == TOTAL

    assert_within_budget(measure(stream, repeat=3), ITERATE_BUDGET_SECONDS, label="iterate 50k")
    assert big_vault.original_count() == TOTAL
