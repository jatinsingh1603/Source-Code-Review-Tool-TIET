"""Property tests of the egress ledger: any sequence of appends verifies and answers its queries."""

import tempfile
from collections import Counter
from datetime import timedelta
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import TokenCounts
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.text import SanitisedText
from codekavach.privacy.egress.ledger import EgressDraft, open_reader, open_writer
from tests.support.factories import FIXED_NOW, SCAN_ID

PAYLOADS = st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=40)
OUTCOMES = st.sampled_from([EgressOutcome.SENT, EgressOutcome.BLOCKED])
CANDIDATES = st.sampled_from(
    [None, "cand_01ARYZ6S410000000000000001", "cand_01ARYZ6S410000000000000002"]
)
ENTRIES = st.lists(st.tuples(PAYLOADS, OUTCOMES, CANDIDATES), min_size=1, max_size=12)


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(entries=ENTRIES)
def test_any_append_sequence_verifies_and_answers_queries(
    entries: list[tuple[str, EgressOutcome, str | None]],
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory) / "state"
        writer = open_writer(state, key_source="ephemeral")
        for index, (text, outcome, candidate) in enumerate(entries):
            body = text + "\n"
            block = "residual_secret" if outcome is EgressOutcome.BLOCKED else None
            writer.append(
                EgressDraft(
                    timestamp=FIXED_NOW + timedelta(seconds=index),
                    scan_id=SCAN_ID,
                    candidate_id=candidate,
                    provider="mock",
                    model="mock-1",
                    task="triage",
                    level=PrivacyLevel.L3,
                    payload_hash=sha256_hex(body),
                    token_counts=TokenCounts(prompt=len(body)),
                    outcome=outcome,
                    block_code=block,
                ),
                SanitisedText(body),
            )
        reader = open_reader(state)
        report = reader.verify_chain()
        assert report.ok and report.entries == len(entries)
        seqs = [record.seq for record in reader.records()]
        assert seqs == list(range(1, len(entries) + 1))
        assert reader.verify_payloads().ok
        counts = Counter(sha256_hex(text + "\n") for text, _, _ in entries)
        for payload_hash, expected in counts.items():
            matched = reader.records_for_payload(payload_hash)
            assert len(matched) == expected
            assert all(record.payload_hash == payload_hash for record in matched)
            assert [record.seq for record in matched] == sorted(record.seq for record in matched)
            stored = reader.payload_text(payload_hash)
            assert stored is not None and sha256_hex(stored.expose()) == payload_hash
