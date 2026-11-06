"""A process that writes to a shared vault; run by ``test_vault_concurrency.py``, not a test.

Usage: ``python vault_writer.py <vault.db> <worker> <batches> <per_batch>``. It prints the
fingerprint of the project salt it saw, so the test can check that every process saw one salt.
"""

import sys
from pathlib import Path

from codekavach.privacy.pseudonymise.generator import PseudonymKind
from codekavach.privacy.pseudonymise.mapping import MappingBatch, MappingEntry
from codekavach.privacy.vault.keys import KeySource, SecretBytes
from codekavach.privacy.vault.store import Vault

KEY = SecretBytes(b"\x33" * 32)


def main(path: str, worker: str, batches: int, per_batch: int) -> None:
    with Vault(Path(path), KeySource.EPHEMERAL, KEY) as vault:
        fingerprint = vault.salt().fingerprint()
        for number in range(batches):
            entries = tuple(
                MappingEntry(
                    f"var_{index + 1}",
                    f"worker_{worker}_batch_{number}_name_{index}",
                    PseudonymKind.VAR,
                    "scope",
                )
                for index in range(per_batch)
            )
            vault.put(MappingBatch(f"scan_{worker}_{number}", entries))
    sys.stdout.write(f"\n{fingerprint}\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
