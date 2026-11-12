"""Unit tests of the egress ledger writer, reader, payload store and index."""

import hashlib
import logging
import os
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import EgressRecord, EgressRecordV1, TokenCounts
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.text import SanitisedText
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.egress.ledger import (
    CHAIN_FILE,
    EgressDraft,
    LedgerError,
    LedgerIntegrityError,
    LedgerKeyError,
    LedgerWriter,
    open_reader,
    open_writer,
)
from tests.support.factories import (
    CANDIDATE_ID,
    FIXED_NOW,
    SCAN_ID,
    VECTOR_PAYLOAD_TEXT,
    make_egress_chain,
)

VECTOR_HASH = (
    "5f8580ae81d45f1645ff37a6bb8d2272e1952e2a277bb703ff164184eeaad992"  # pragma: allowlist secret
)
POSIX = os.name == "posix"


def text_of(index: int) -> str:
    return f"def fn_{index}(param_{index}):\n    return param_{index}\n"


def draft_for(
    text: str,
    index: int,
    *,
    outcome: EgressOutcome = EgressOutcome.SENT,
    candidate: str | None = None,
    block_code: str | None = None,
    ref_seq: int | None = None,
    payload_hash: str | None = None,
) -> EgressDraft:
    return EgressDraft(
        timestamp=FIXED_NOW + timedelta(seconds=index),
        scan_id=SCAN_ID,
        candidate_id=candidate,
        provider="mock",
        model="mock-1",
        task="triage",
        level=PrivacyLevel.L3,
        payload_hash=payload_hash or sha256_hex(text),
        token_counts=TokenCounts(prompt=len(text)),
        outcome=outcome,
        block_code=block_code,
        ref_seq=ref_seq,
    )


@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "state"


@pytest.fixture
def writer(state: Path) -> LedgerWriter:
    # The ephemeral key source is available only under pytest and lives for this process.
    return open_writer(state, key_source="ephemeral")


def test_entry_hash_reproduces_the_e02_18_vector(state: Path) -> None:
    chain = make_egress_chain(1)
    writer = open_writer(state, key_source="ephemeral")
    sealed = writer.append(chain[0], SanitisedText(VECTOR_PAYLOAD_TEXT))
    assert sealed == chain[0]
    assert sealed.schema_version == EgressRecord.SCHEMA_VERSION
    # The published version-1 vector is unchanged; the writer now seals version 2 (E25-03).
    assert make_egress_chain(1, record_class=EgressRecordV1)[0].entry_hash == VECTOR_HASH


def test_genesis_and_seq_assignment(writer: LedgerWriter) -> None:
    texts = [text_of(i) for i in range(3)]
    sealed = [
        writer.append(draft_for(text, i), SanitisedText(text)) for i, text in enumerate(texts)
    ]
    assert [record.seq for record in sealed] == [1, 2, 3]
    assert sealed[0].prev_hash == "0" * 64
    assert sealed[1].prev_hash == sealed[0].entry_hash
    assert sealed[2].prev_hash == sealed[1].entry_hash
    assert writer.verify_chain().ok and writer.verify_chain().entries == 3


def test_payload_must_hash_to_payload_hash(writer: LedgerWriter) -> None:
    with pytest.raises(ValueError, match="does not hash"):
        writer.append(draft_for(text_of(1), 1), SanitisedText(text_of(2)))


def test_payload_must_be_sanitised_text(writer: LedgerWriter) -> None:
    with pytest.raises(TypeError):
        writer.append(draft_for(text_of(1), 1), text_of(1))  # type: ignore[arg-type]


def test_follow_up_needs_a_stored_payload(writer: LedgerWriter) -> None:
    text = text_of(1)
    first = writer.append(draft_for(text, 1), SanitisedText(text))
    follow_up = draft_for(text, 2, outcome=EgressOutcome.COMPLETED, ref_seq=first.seq)
    completed = writer.append(follow_up)
    assert completed.seq == 2
    with pytest.raises(ValueError, match="no stored payload"):
        writer.append(draft_for(text_of(9), 3, outcome=EgressOutcome.COMPLETED, ref_seq=1))


def test_blocked_and_dry_run_entries_keep_their_payloads(writer: LedgerWriter, state: Path) -> None:
    blocked = text_of(4)
    dry = text_of(5)
    writer.append(
        draft_for(
            blocked,
            1,
            outcome=EgressOutcome.BLOCKED,
            block_code="residual_secret",
            candidate=str(CANDIDATE_ID),
        ),
        SanitisedText(blocked),
    )
    writer.append(draft_for(dry, 2), SanitisedText(dry))
    reader = open_reader(state, key=None)
    assert reader.payload_text(sha256_hex(blocked)) == SanitisedText(blocked)
    assert reader.payload_text(sha256_hex(dry)) == SanitisedText(dry)
    assert [r.outcome for r in reader.records(None)] == [
        EgressOutcome.BLOCKED,
        EgressOutcome.SENT,
    ]


def test_identical_payloads_are_stored_once_with_a_reference_count(
    writer: LedgerWriter, state: Path
) -> None:
    text = text_of(7)
    for index in range(3):
        writer.append(draft_for(text, index), SanitisedText(text))
    bodies = [p for p in (state / "ledger" / "payloads").rglob("*") if p.is_file()]
    assert len(bodies) == 1
    reader = open_reader(state)
    assert len(reader.records_for_payload(sha256_hex(text))) == 3


def test_stored_bytes_do_not_contain_the_payload_text(writer: LedgerWriter, state: Path) -> None:
    text = "payload-marker-" + "x" * 40 + "\n"
    writer.append(draft_for(text, 1), SanitisedText(text))
    for body in (state / "ledger" / "payloads").rglob("*"):
        if body.is_file():
            assert text.encode() not in body.read_bytes()
            assert b"payload-marker" not in body.read_bytes()


def test_plaintext_store_when_encryption_is_off(tmp_path: Path) -> None:
    state = tmp_path / "plain"
    writer = open_writer(state, encrypt_at_rest=False)
    text = "plain body\r\nwith crlf\n"
    writer.append(draft_for(text, 1), SanitisedText(text))
    body = state / "ledger" / "payloads" / sha256_hex(text)[:2] / sha256_hex(text)
    assert body.read_bytes() == text.encode("utf-8")
    with pytest.raises(LedgerError, match="encryption setting"):
        open_writer(state, encrypt_at_rest=True, key_source="ephemeral")


def test_records_for_candidate_pairs_byte_identical_payloads(
    writer: LedgerWriter, state: Path
) -> None:
    candidate = str(CANDIDATE_ID)
    text = "line one\r\nline two\n\tindented\n"
    writer.append(draft_for(text, 1, candidate=candidate), SanitisedText(text))
    writer.append(draft_for("other\n", 2, candidate="cand_" + "0" * 26), SanitisedText("other\n"))
    reader = open_reader(state)
    attempts = reader.records_for_candidate(candidate)
    assert [record.seq for record in attempts] == [1]
    paired = reader.payload_text(attempts[0].payload_hash)
    assert paired is not None and paired.expose() == text


def test_totals_match_a_hand_computed_expectation(writer: LedgerWriter, state: Path) -> None:
    sent_text = text_of(1)
    writer.append(draft_for(sent_text, 1), SanitisedText(sent_text))
    writer.append(
        draft_for(text_of(2), 2, outcome=EgressOutcome.BLOCKED, block_code="residual_secret"),
        SanitisedText(text_of(2)),
    )
    totals = open_reader(state).totals()
    assert totals.requests_sent == 1
    assert totals.requests_blocked == 1
    assert totals.requests_failed == 0
    assert totals.prompt_tokens == len(sent_text)
    assert dict(totals.levels)[PrivacyLevel.L3] == 1


def test_reader_scan_filter_and_empty_ledger(tmp_path: Path) -> None:
    empty = open_reader(tmp_path / "nothing")
    assert list(empty.records()) == []
    assert empty.verify_chain().ok and empty.verify_chain().entries == 0
    assert empty.payload_text(sha256_hex("x")) is None
    assert not (tmp_path / "nothing").exists()


def test_scan_filter(writer: LedgerWriter, state: Path) -> None:
    writer.append(draft_for(text_of(1), 1), SanitisedText(text_of(1)))
    reader = open_reader(state)
    assert len(list(reader.records(str(SCAN_ID)))) == 1
    assert list(reader.records("scan_01ARYZ6S41000000000000000Z")) == []


def test_index_loss_is_rebuilt_and_every_query_still_answers(
    writer: LedgerWriter, state: Path
) -> None:
    text = text_of(3)
    writer.append(draft_for(text, 1, candidate=str(CANDIDATE_ID)), SanitisedText(text))
    index = state / "ledger" / "index.sqlite3"
    assert open_reader(state).payload_text(sha256_hex(text)) is not None  # builds the index
    assert index.exists()
    index.unlink()
    reader = open_reader(state)
    assert reader.verify_chain().ok
    assert reader.verify_payloads().ok
    assert reader.payload_text(sha256_hex(text)) == SanitisedText(text)
    assert len(reader.records_for_payload(sha256_hex(text))) == 1
    assert len(reader.records_for_candidate(str(CANDIDATE_ID))) == 1
    assert index.exists()


def test_prune_keeps_payloads_needed_by_recent_records(writer: LedgerWriter, state: Path) -> None:
    old = text_of(1)
    recent = text_of(2)
    writer.append(draft_for(old, 1), SanitisedText(old))
    writer.append(draft_for(recent, 100), SanitisedText(recent))
    cutoff = FIXED_NOW + timedelta(seconds=50)
    assert writer.prune(cutoff) == 1
    report = open_reader(state).verify_payloads()
    assert report.ok
    assert report.pruned_seqs == (1,)
    assert open_reader(state).payload_text(sha256_hex(old)) is None
    assert open_reader(state).payload_text(sha256_hex(recent)) == SanitisedText(recent)
    assert open_reader(state).verify_chain().ok


def test_a_pruned_payload_can_be_stored_again(writer: LedgerWriter, state: Path) -> None:
    text = text_of(1)
    writer.append(draft_for(text, 1), SanitisedText(text))
    writer.prune(FIXED_NOW + timedelta(seconds=50))
    writer.append(draft_for(text, 200), SanitisedText(text))
    report = open_reader(state).verify_payloads()
    assert report.ok and report.pruned_seqs == ()


def test_payload_text_is_none_for_an_unknown_hash(writer: LedgerWriter) -> None:
    assert writer.payload_text(sha256_hex("never stored")) is None


def test_bad_hash_argument_is_refused(writer: LedgerWriter) -> None:
    with pytest.raises(ValueError):
        writer.payload_text("not-a-hash")


def test_encrypted_payloads_need_the_key_to_read(writer: LedgerWriter, state: Path) -> None:
    text = text_of(1)
    writer.append(draft_for(text, 1), SanitisedText(text))
    other = open_reader(state, key=SecretStr("ab" * 32))
    with pytest.raises(LedgerKeyError):
        other.payload_text(sha256_hex(text))


def test_explicit_key_round_trip(tmp_path: Path) -> None:
    state = tmp_path / "keyed"
    key = SecretStr("cd" * 32)
    writer = open_writer(state, key=key)
    text = text_of(1)
    writer.append(draft_for(text, 1), SanitisedText(text))
    assert open_reader(state, key=key).payload_text(sha256_hex(text)) == SanitisedText(text)
    with pytest.raises(LedgerKeyError):
        open_reader(state).payload_text(sha256_hex(text))


def test_no_payload_text_in_logs_or_reports(
    writer: LedgerWriter, state: Path, caplog: pytest.LogCaptureFixture
) -> None:
    secret_like = "SECRET-MARKER-" + "q" * 30 + "\n"  # pragma: allowlist secret
    caplog.set_level(logging.DEBUG)
    writer.append(draft_for(secret_like, 1), SanitisedText(secret_like))
    report = open_reader(state).verify_payloads()
    rendered = repr(report) + repr(open_reader(state).verify_chain())
    assert "SECRET-MARKER" not in caplog.text
    assert "SECRET-MARKER" not in rendered


@pytest.mark.skipif(not POSIX, reason="file modes are a POSIX concept")
def test_files_are_created_with_restrictive_modes(writer: LedgerWriter, state: Path) -> None:
    writer.append(draft_for(text_of(1), 1), SanitisedText(text_of(1)))
    ledger = state / "ledger"
    assert ledger.stat().st_mode & 0o777 == 0o700
    assert (ledger / CHAIN_FILE).stat().st_mode & 0o777 == 0o600
    assert (ledger / "header.json").stat().st_mode & 0o777 == 0o600


def test_writer_refuses_a_chain_with_an_incomplete_last_line(
    writer: LedgerWriter, state: Path
) -> None:
    writer.append(draft_for(text_of(1), 1), SanitisedText(text_of(1)))
    chain = state / "ledger" / CHAIN_FILE
    with chain.open("ab") as handle:
        handle.write(b'{"seq": 2, "partial')
    with pytest.raises(LedgerIntegrityError, match="incomplete line"):
        open_writer(state, key_source="ephemeral").append(
            draft_for(text_of(2), 2), SanitisedText(text_of(2))
        )


def test_layout_object_is_accepted(tmp_path: Path) -> None:
    layout = StateLayout(tmp_path / "layout")
    writer = open_writer(layout, key_source="ephemeral")
    writer.append(draft_for(text_of(1), 1), SanitisedText(text_of(1)))
    assert open_reader(layout).verify_chain().entries == 1


def test_fabricated_record_argument_is_resealed(writer: LedgerWriter, state: Path) -> None:
    chain = make_egress_chain(1)
    sealed = writer.append(chain[0], SanitisedText(VECTOR_PAYLOAD_TEXT))
    assert sealed.seq == 1
    assert isinstance(sealed, EgressRecord)
    assert hashlib.sha256(VECTOR_PAYLOAD_TEXT.encode()).hexdigest() == sealed.payload_hash


def test_draft_timestamp_never_regresses(writer: LedgerWriter) -> None:
    writer.append(draft_for(text_of(1), 50), SanitisedText(text_of(1)))
    later = writer.append(draft_for(text_of(2), 1), SanitisedText(text_of(2)))
    assert later.timestamp >= FIXED_NOW + timedelta(seconds=50)
    assert writer.verify_chain().ok


def test_a_dry_run_entry_stores_its_payload_and_verifies(state: Path) -> None:
    """E12-04b: a dry-run delivery is ledgered as ``not_sent_dry_run`` with the payload kept."""
    writer = open_writer(state, key_source="ephemeral")
    text = text_of(1)
    sealed = writer.append(
        draft_for(text, 1, outcome=EgressOutcome.NOT_SENT_DRY_RUN), SanitisedText(text)
    )
    assert sealed.outcome is EgressOutcome.NOT_SENT_DRY_RUN
    assert EgressRecord.model_validate_json(sealed.model_dump_json()) == sealed
    stored = writer.payload_text(sealed.payload_hash)
    assert stored is not None and stored.expose() == text
    assert writer.verify_chain().ok and writer.verify_payloads().ok
