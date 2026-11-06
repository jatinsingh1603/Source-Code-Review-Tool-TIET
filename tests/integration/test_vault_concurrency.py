"""Writers that share a vault never share a nonce, and never corrupt it (E10-01).

AES-GCM breaks if a nonce repeats under one key, so the counter that makes nonces is the thing
under test: several processes and several threads write to one file at the same time, including
the very first write that creates it.
"""

import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault

pytestmark = pytest.mark.integration

WRITER = Path(__file__).with_name("vault_writer.py")
KEY = SecretBytes(b"\x33" * 32)
PROCESSES = 3
BATCHES = 8
PER_BATCH = 10


def database_rows(path: Path, sql: str) -> list[tuple[Any, ...]]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def test_processes_writing_together_never_repeat_a_nonce(tmp_path: Path) -> None:
    path = tmp_path / "state" / "vault" / "vault.db"
    command = [sys.executable, str(WRITER), str(path)]
    workers = [
        subprocess.Popen(
            [*command, str(index), str(BATCHES), str(PER_BATCH)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(PROCESSES)
    ]
    outputs = [worker.communicate(timeout=240) for worker in workers]
    assert [worker.returncode for worker in workers] == [0] * PROCESSES, outputs
    assert len({out.split()[-1] for out, _ in outputs}) == 1, (
        "every process must see one project salt"
    )

    total = PROCESSES * BATCHES * PER_BATCH
    nonces = [row[0] for row in database_rows(path, "SELECT nonce FROM records")]
    (salt_nonce,) = database_rows(path, "SELECT salt_nonce FROM header")[0]
    (counter,) = database_rows(path, "SELECT nonce_counter FROM header")[0]
    assert len(nonces) == total
    assert len({*nonces, salt_nonce}) == total + 1 == counter

    with Vault(path, KeySource.EPHEMERAL, KEY, create=False) as vault:
        assert vault.original_count(1) == total
        assert len(set(vault.iter_originals(min_len=1))) == total
        assert vault.lookup("var_1", scan_id="scan_0_0") == "worker_0_batch_0_name_0"


def test_threads_writing_together_never_repeat_a_nonce(tmp_path: Path) -> None:
    path = tmp_path / "vault" / "vault.db"
    vault = Vault(path, KeySource.EPHEMERAL, KEY)
    errors: list[BaseException] = []

    def write(worker: int) -> None:
        try:
            for number in range(BATCHES):
                entries = tuple(
                    MappingEntry(
                        f"var_{index + 1}",
                        f"thread_{worker}_{number}_{index}",
                        PseudonymKind.VAR,
                        "scope",
                    )
                    for index in range(PER_BATCH)
                )
                vault.put(MappingBatch(f"scan_{worker}_{number}", entries))
        except BaseException as error:  # noqa: BLE001 - reported by the test thread
            errors.append(error)

    threads = [threading.Thread(target=write, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=240)
    vault.close()
    assert not errors, errors
    nonces = [row[0] for row in database_rows(path, "SELECT nonce FROM records")]
    assert len(nonces) == 6 * BATCHES * PER_BATCH == len(set(nonces))
    (counter,) = database_rows(path, "SELECT nonce_counter FROM header")[0]
    assert counter == len(nonces)
