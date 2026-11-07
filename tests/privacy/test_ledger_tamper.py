"""Invariant tests for the egress ledger's tamper evidence (E12-03).

Every row of the tamper matrix in the issue is one test. Each mutation must produce a named
verification outcome at a specific ``seq``, and no mutation may produce a passing report. The chain
and the payload store are checked independently: a corrupted payload fails ``verify_payloads`` and
not ``verify_chain``, and the reverse.
"""

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import EgressRecord, TokenCounts
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.text import SanitisedText
from codekavach.privacy.egress.ledger import ChainReport, EgressDraft, open_reader, open_writer
from tests.support.factories import FIXED_NOW, SCAN_ID

CHAIN = Path("ledger") / "chain.ndjson"
PAYLOADS = Path("ledger") / "payloads"


def text_of(index: int) -> str:
    return f"def fn_{index}(param_{index}):\n    return param_{index}\n"


def draft(index: int) -> EgressDraft:
    text = text_of(index)
    return EgressDraft(
        timestamp=FIXED_NOW + timedelta(seconds=index),
        scan_id=SCAN_ID,
        candidate_id=None,
        provider="mock",
        model="mock-1",
        task="triage",
        level=PrivacyLevel.L3,
        payload_hash=sha256_hex(text),
        token_counts=TokenCounts(prompt=10),
        outcome=EgressOutcome.SENT,
    )


def build(state: Path, *, encrypt: bool, entries: int = 4) -> None:
    writer = open_writer(
        state, encrypt_at_rest=encrypt, key_source="ephemeral" if encrypt else "keyring"
    )
    for index in range(1, entries + 1):
        writer.append(draft(index), SanitisedText(text_of(index)))


def lines_of(state: Path) -> list[bytes]:
    return (state / CHAIN).read_bytes().splitlines(keepends=True)


def write_lines(state: Path, lines: list[bytes]) -> None:
    (state / CHAIN).write_bytes(b"".join(lines))


def edited(line: bytes, **changes: object) -> bytes:
    document = json.loads(line)
    document.update(changes)
    return json.dumps(document, separators=(",", ":")).encode("utf-8") + b"\n"


@pytest.fixture
def state(tmp_path: Path) -> Path:
    directory = tmp_path / "state"
    build(directory, encrypt=True)
    return directory


def chain_report(state: Path) -> ChainReport:
    return open_reader(state).verify_chain()


def test_intact_chain_verifies(state: Path) -> None:
    report = chain_report(state)
    assert report.ok and report.entries == 4 and report.first_bad_seq is None


def test_modify_one_field_of_one_entry(state: Path) -> None:
    lines = lines_of(state)
    lines[1] = edited(lines[1], provider="elsewhere")
    write_lines(state, lines)
    report = chain_report(state)
    assert not report.ok
    assert (report.first_bad_seq, report.reason) == (2, "entry_hash_mismatch")


def test_swap_two_entries(state: Path) -> None:
    lines = lines_of(state)
    lines[1], lines[2] = lines[2], lines[1]
    write_lines(state, lines)
    report = chain_report(state)
    assert not report.ok
    assert (report.first_bad_seq, report.reason) == (2, "seq_gap")


def test_delete_an_entry(state: Path) -> None:
    lines = lines_of(state)
    del lines[1]
    write_lines(state, lines)
    report = chain_report(state)
    assert not report.ok
    assert (report.first_bad_seq, report.reason) == (2, "seq_gap")


def test_insert_a_fabricated_entry_with_a_stale_prev_hash(state: Path) -> None:
    lines = lines_of(state)
    records = [EgressRecord.model_validate_json(line) for line in lines]
    forged = records[3].model_copy(update={"seq": 5, "prev_hash": records[2].entry_hash})
    forged = forged.model_copy(update={"entry_hash": forged.compute_entry_hash()})
    write_lines(state, [*lines, forged.model_dump_json().encode("utf-8") + b"\n"])
    report = chain_report(state)
    assert not report.ok
    assert (report.first_bad_seq, report.reason) == (5, "prev_hash_mismatch")


def test_truncate_mid_line(state: Path) -> None:
    raw = (state / CHAIN).read_bytes()
    (state / CHAIN).write_bytes(raw[:-20])
    report = chain_report(state)
    assert not report.ok
    assert (report.first_bad_seq, report.reason) == (4, "truncated_line")


def test_a_garbage_line_in_the_middle_is_named_as_malformed(state: Path) -> None:
    lines = lines_of(state)
    lines[1] = b"this is not json" + chr(10).encode("ascii")
    write_lines(state, lines)
    report = chain_report(state)
    assert not report.ok
    assert (report.first_bad_seq, report.reason) == (2, "malformed_line")


def test_replace_a_payload_file_with_other_bytes(state: Path) -> None:
    payload = sha256_hex(text_of(2))
    body = state / PAYLOADS / payload[:2] / payload
    body.write_bytes(os.urandom(64))
    reader = open_reader(state, key=None)
    report = reader.verify_payloads()
    assert not report.ok
    assert [(issue.seq, issue.reason) for issue in report.issues] == [(2, "payload_unreadable")]
    assert reader.verify_chain().ok


def test_rename_a_payload_file(tmp_path: Path) -> None:
    state = tmp_path / "plain"
    build(state, encrypt=False)
    source = sha256_hex(text_of(1))
    target = sha256_hex(text_of(3))
    source_path = state / PAYLOADS / source[:2] / source
    target_path = state / PAYLOADS / target[:2] / target
    target_path.write_bytes(
        source_path.read_bytes()
    )  # the file now holds text 1 under text 3's name
    report = open_reader(state).verify_payloads()
    assert not report.ok
    assert [(issue.seq, issue.reason) for issue in report.issues] == [(3, "payload_mismatch")]
    assert open_reader(state).verify_chain().ok


def test_delete_a_payload_file(state: Path) -> None:
    payload = sha256_hex(text_of(2))
    (state / PAYLOADS / payload[:2] / payload).unlink()
    report = open_reader(state, key=None).verify_payloads()
    assert not report.ok
    assert [(issue.seq, issue.reason) for issue in report.issues] == [(2, "payload_missing")]
    assert open_reader(state).verify_chain().ok


def test_plaintext_payload_content_change_is_a_mismatch(tmp_path: Path) -> None:
    state = tmp_path / "plain"
    build(state, encrypt=False)
    payload = sha256_hex(text_of(4))
    (state / PAYLOADS / payload[:2] / payload).write_bytes(b"altered after recording\n")
    report = open_reader(state).verify_payloads()
    assert [(issue.seq, issue.reason) for issue in report.issues] == [(4, "payload_mismatch")]
    assert open_reader(state).verify_chain().ok


def test_chain_and_payload_checks_are_independent(state: Path) -> None:
    payload = sha256_hex(text_of(1))
    (state / PAYLOADS / payload[:2] / payload).unlink()
    assert chain_report(state).ok
    assert not open_reader(state, key=None).verify_payloads().ok

    lines = lines_of(state)
    lines[0] = edited(lines[0], model="other")
    write_lines(state, lines)
    assert not chain_report(state).ok
    issues = open_reader(state, key=None).verify_payloads().issues
    assert [(issue.seq, issue.reason) for issue in issues] == [(1, "entry_unreadable")]


def test_no_passing_report_for_any_chain_mutation(state: Path) -> None:
    original = lines_of(state)
    mutations = [
        original[1:],  # the first entry deleted
        original[:1] + original[2:],  # the second entry deleted
        original[:1] + original[2:3] + original[1:2] + original[3:],  # two entries swapped
        [original[0][:-5], *original[1:]],  # the first entry truncated
    ]
    for mutated in mutations:
        write_lines(state, mutated)
        assert not chain_report(state).ok
        write_lines(state, original)
