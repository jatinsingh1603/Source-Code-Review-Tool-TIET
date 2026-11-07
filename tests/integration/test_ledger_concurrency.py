"""Integration tests of the egress ledger: concurrent writers, crashes and truncation (E12-03)."""

import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import TokenCounts
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.text import SanitisedText
from codekavach.privacy.egress.ledger import (
    EgressDraft,
    LedgerIntegrityError,
    LedgerWriter,
    open_reader,
    open_writer,
)
from tests.support.factories import SCAN_ID

KEY = "ef" * 32
WORKER = """
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import SecretStr

from codekavach.core.models.canonical import sha256_hex
from codekavach.core.models.egress import TokenCounts
from codekavach.core.models.enums import EgressOutcome, PrivacyLevel
from codekavach.core.models.text import SanitisedText
from codekavach.privacy.egress.ledger import EgressDraft, open_writer

state, key, tag, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
writer = open_writer(Path(state), key=SecretStr(key))
for index in range(count):
    text = f"{tag} payload {index}\\n"
    writer.append(
        EgressDraft(
            timestamp=datetime.now(UTC),
            scan_id="SCAN_ID",
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
""".replace("SCAN_ID", str(SCAN_ID))


def draft_for(index: int, text: str) -> EgressDraft:
    return EgressDraft(
        timestamp=datetime.now(UTC),
        scan_id=SCAN_ID,
        candidate_id=None,
        provider="mock",
        model="mock-1",
        task="triage",
        level=PrivacyLevel.L3,
        payload_hash=sha256_hex(text),
        token_counts=TokenCounts(prompt=len(text)),
        outcome=EgressOutcome.SENT,
    )


def test_two_processes_append_one_contiguous_chain(tmp_path: Path) -> None:
    state = tmp_path / "state"
    open_writer(state, key=SecretStr(KEY))  # create the header before the race
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", WORKER, str(state), KEY, tag, "15"],
        )
        for tag in ("alpha", "bravo")
    ]
    for worker in workers:
        assert worker.wait(timeout=120) == 0
    reader = open_reader(state, key=SecretStr(KEY))
    report = reader.verify_chain()
    assert report.ok and report.entries == 30
    seqs = [record.seq for record in reader.records()]
    assert seqs == list(range(1, 31))
    assert reader.verify_payloads().ok


def test_threads_sharing_one_state_directory_stay_contiguous(tmp_path: Path) -> None:
    state = tmp_path / "threads"
    writers = [open_writer(state, key_source="ephemeral") for _ in range(4)]

    def run(writer: LedgerWriter, number: int) -> None:
        for index in range(10):
            text = f"thread {number} entry {index}\n"
            writer.append(draft_for(index, text), SanitisedText(text))

    with ThreadPoolExecutor(max_workers=4) as pool:
        for number, writer in enumerate(writers):
            pool.submit(run, writer, number)
    reader = open_reader(state)
    assert reader.verify_chain().entries == 40
    assert [record.seq for record in reader.records()] == list(range(1, 41))


def test_crash_between_payload_write_and_chain_append_leaves_an_orphan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "crash"
    writer = open_writer(state, key_source="ephemeral")
    kept = "kept payload\n"
    writer.append(draft_for(1, kept), SanitisedText(kept))
    lost = "payload whose chain line never landed\n"

    def crash(self: LedgerWriter, record: object) -> None:
        raise OSError("simulated power loss before the chain append")

    monkeypatch.setattr(LedgerWriter, "_write_line", crash)
    with pytest.raises(OSError, match="simulated"):
        writer.append(draft_for(2, lost), SanitisedText(lost))
    monkeypatch.undo()

    reader = open_reader(state)
    assert reader.verify_chain().entries == 1
    report = reader.verify_payloads()
    assert report.ok
    assert sha256_hex(lost) in report.orphans
    assert sha256_hex(kept) not in report.orphans

    recovered = open_writer(state, key_source="ephemeral")
    followed = recovered.append(
        draft_for(3, "after the crash\n"), SanitisedText("after the crash\n")
    )
    assert followed.seq == 2
    assert open_reader(state).verify_chain().ok


def test_mid_line_truncation_is_reported_and_blocks_appends(tmp_path: Path) -> None:
    state = tmp_path / "truncated"
    writer = open_writer(state, key_source="ephemeral")
    for index in range(2):
        text = f"entry {index}\n"
        writer.append(draft_for(index, text), SanitisedText(text))
    chain = state / "ledger" / "chain.ndjson"
    chain.write_bytes(chain.read_bytes()[:-15])
    report = open_reader(state).verify_chain()
    assert not report.ok
    assert (report.first_bad_seq, report.reason) == (2, "truncated_line")
    with pytest.raises(LedgerIntegrityError, match="incomplete line"):
        open_writer(state, key_source="ephemeral").append(
            draft_for(9, "next\n"), SanitisedText("next\n")
        )
