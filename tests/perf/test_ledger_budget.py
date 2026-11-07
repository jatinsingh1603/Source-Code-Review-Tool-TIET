"""Performance budgets of the egress ledger (E12-03).

An append, with payload encryption and fsync, takes under 15 ms. Walking and verifying a
10 000-entry chain takes under 3 s. The budgets scale with the performance factor.
"""

import itertools
from datetime import timedelta
from pathlib import Path

import pytest

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import EgressRecord, TokenCounts
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.text import SanitisedText
from codekavach.privacy.egress.ledger import EgressDraft, open_reader, open_writer
from tests.support.factories import FIXED_NOW, SCAN_ID
from tests.support.perf import assert_within_budget, median_seconds

APPEND_BUDGET_SECONDS = 0.015
VERIFY_BUDGET_SECONDS = 3.0
CHAIN_LENGTH = 10_000


@pytest.mark.perf
def test_append_with_encryption_and_fsync_stays_within_budget(tmp_path: Path) -> None:
    writer = open_writer(tmp_path / "append", key_source="ephemeral")
    counter = itertools.count()
    payload = "def fn(param):\n    return param\n" * 4

    def append() -> None:
        number = next(counter)
        text = f"{payload}# {number}\n"
        writer.append(
            EgressDraft(
                timestamp=FIXED_NOW + timedelta(seconds=number),
                scan_id=SCAN_ID,
                candidate_id=None,
                provider="mock",
                model="mock-1",
                task="triage",
                level=PrivacyLevel.L3,
                payload_hash=sha256_hex(text),
                token_counts=TokenCounts(prompt=len(text)),
                outcome=EgressOutcome.SENT,
            ),
            SanitisedText(text),
        )

    append()  # warm the index and the key
    assert_within_budget(
        median_seconds(append, repeat=15), APPEND_BUDGET_SECONDS, label="ledger append"
    )


@pytest.mark.perf
def test_verifying_ten_thousand_entries_stays_within_budget(tmp_path: Path) -> None:
    state = tmp_path / "long"
    open_writer(state, encrypt_at_rest=False)  # creates the ledger header
    chain: list[EgressRecord] = []
    for index in range(CHAIN_LENGTH):
        previous = chain[-1] if chain else None
        chain.append(
            EgressRecord.seal(
                prev=previous,
                timestamp=FIXED_NOW + timedelta(seconds=index),
                scan_id=SCAN_ID,
                candidate_id=None,
                provider="mock",
                model="mock-1",
                task="triage",
                level=PrivacyLevel.L3,
                payload_hash=sha256_hex(f"entry {index}"),
                token_counts=TokenCounts(prompt=1),
                outcome=EgressOutcome.SENT,
            )
        )
    lines = b"".join(record.model_dump_json().encode("utf-8") + b"\n" for record in chain)
    (state / "ledger" / "chain.ndjson").write_bytes(lines)
    reader = open_reader(state)
    assert reader.verify_chain().entries == CHAIN_LENGTH
    assert_within_budget(
        median_seconds(reader.verify_chain, repeat=3),
        VERIFY_BUDGET_SECONDS,
        label="verify 10 000 entries",
    )
