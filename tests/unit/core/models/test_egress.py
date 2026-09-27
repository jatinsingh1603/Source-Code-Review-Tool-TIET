import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import DataClassification, ModelError, PrivacyLevel, canonical_json
from codekavach.core.models.egress import GENESIS_PREV_HASH, EgressRecord, TokenCounts
from codekavach.core.models.enums import EgressOutcome
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).parent / "golden" / "ledger_chain_v1.jsonl"
T0 = datetime(2026, 10, 5, 4, 30, tzinfo=UTC)
SCAN = "scan_01ARYZ6S410000000000000000"
CAND_1 = "cand_01ARYZ6S410000000000000001"
CAND_2 = "cand_01ARYZ6S410000000000000002"
# pragma: allowlist nextline secret
PAYLOAD_HASH = "564f164d9b913418ddc386d366d422ebd5cb11cd0ff1469f6b3aed202849e847"
# pragma: allowlist nextline secret
VECTOR_HASH = "5f8580ae81d45f1645ff37a6bb8d2272e1952e2a277bb703ff164184eeaad992"
VECTOR_BYTES = (
    '{"block_code":null,"candidate_id":"cand_01ARYZ6S410000000000000001","level":"L3",'
    '"model":"mock-1","outcome":"sent","payload_hash":"' + PAYLOAD_HASH + '",'
    '"prev_hash":"' + GENESIS_PREV_HASH + '","provider":"mock","ref_seq":null,'
    '"request_hash":null,"scan_id":"scan_01ARYZ6S410000000000000000","schema_version":1,'
    '"seq":1,"task":"triage","timestamp":"2026-10-05T04:30:00.000000Z",'
    '"token_counts":{"completion":null,"estimated":true,"prompt":120}}'
)
EXPECTED_PROPERTIES = {
    "schema_version",
    "seq",
    "timestamp",
    "scan_id",
    "candidate_id",
    "provider",
    "model",
    "task",
    "level",
    "payload_hash",
    "request_hash",
    "prev_hash",
    "entry_hash",
    "token_counts",
    "outcome",
    "block_code",
    "ref_seq",
}


def seal(prev: EgressRecord | None = None, **overrides: Any) -> EgressRecord:
    fields: dict[str, Any] = {
        "prev": prev,
        "timestamp": T0 if prev is None else prev.timestamp + timedelta(seconds=1),
        "scan_id": SCAN,
        "candidate_id": CAND_1,
        "provider": "mock",
        "model": "mock-1",
        "task": "triage",
        "level": PrivacyLevel.L3,
        "payload_hash": PAYLOAD_HASH,
        "token_counts": TokenCounts(prompt=120),
        "outcome": EgressOutcome.SENT,
    }
    fields.update(overrides)
    return EgressRecord.seal(**fields)


def golden_chain() -> list[EgressRecord]:
    sent = seal()
    completed = seal(
        sent,
        outcome=EgressOutcome.COMPLETED,
        ref_seq=1,
        token_counts=TokenCounts(prompt=118, completion=64, estimated=False),
    )
    blocked = seal(
        completed,
        candidate_id=CAND_2,
        outcome=EgressOutcome.BLOCKED,
        block_code="residual_secret",
        token_counts=TokenCounts(prompt=80),
    )
    return [sent, completed, blocked]


def test_vector() -> None:
    record = seal()
    assert canonical_json(record, exclude=frozenset({"entry_hash"})).decode() == VECTOR_BYTES
    assert record.entry_hash == VECTOR_HASH
    assert record.seq == 1
    assert record.prev_hash == GENESIS_PREV_HASH
    assert EgressRecord.MIGRATABLE is False
    assert EgressRecord.DATA_CLASSIFICATION is DataClassification.METADATA
    assert TokenCounts.DATA_CLASSIFICATION is DataClassification.METADATA


def test_golden_chain() -> None:
    chain = golden_chain()
    text = "".join(record.model_dump_json() + "\n" for record in chain)
    assert_matches_golden(text, GOLDEN)
    stored = [
        EgressRecord.model_validate_json(line)
        for line in GOLDEN.read_text(encoding="utf-8").splitlines()
    ]
    assert stored[0].entry_hash == VECTOR_HASH
    previous: EgressRecord | None = None
    for record in stored:
        assert record.entry_hash == record.compute_entry_hash()
        record.verify_link(previous)
        previous = record


def test_any_field_change_fails_validation() -> None:
    record = seal()
    changes: dict[str, Any] = {
        "seq": 2,
        "timestamp": T0 + timedelta(seconds=1),
        "provider": "other",
        "model": "mock-2",
        "task": "explain",
        "level": PrivacyLevel.L2,
        "payload_hash": "1" * 64,
        "request_hash": "2" * 64,
        "token_counts": TokenCounts(prompt=121),
        "candidate_id": CAND_2,
    }
    for name, value in changes.items():
        tampered = record.model_copy(update={name: value})
        with pytest.raises(ValidationError):
            EgressRecord.model_validate(tampered.model_dump())
    data = json.loads(record.model_dump_json())
    data["provider"] = "evil"
    with pytest.raises(ValidationError, match="entry_hash"):
        EgressRecord.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "overrides",
    [
        {"outcome": EgressOutcome.BLOCKED},
        {"block_code": "residual_secret"},
        {"outcome": EgressOutcome.COMPLETED},
        {"outcome": EgressOutcome.FAILED},
        {"ref_seq": 1},
        {"payload_hash": PAYLOAD_HASH.upper()},
        {"block_code": "has space", "outcome": EgressOutcome.BLOCKED},
        {"request_hash": "a" * 63},
        {"provider": "mo\x00ck"},
        {"task": "Triage"},
    ],
    ids=[
        "blocked-without-code",
        "sent-with-code",
        "completed-without-ref",
        "failed-without-ref",
        "sent-with-ref",
        "upper-hex",
        "code-with-space",
        "short-request-hash",
        "control-char",
        "task-slug",
    ],
)
def test_rejected_combinations(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        seal(**overrides)


def test_ref_seq_must_be_earlier() -> None:
    first = seal()
    with pytest.raises(ValidationError, match="earlier"):
        seal(first, outcome=EgressOutcome.COMPLETED, ref_seq=2)


def test_seq_zero_and_bad_genesis_rejected() -> None:
    data = json.loads(seal().model_dump_json())
    data["seq"] = 0
    with pytest.raises(ValidationError):
        EgressRecord.model_validate(data)
    data = json.loads(seal().model_dump_json())
    data["prev_hash"] = "1" * 64
    with pytest.raises(ValidationError, match="genesis"):
        EgressRecord.model_validate(data)


def test_schema_properties() -> None:
    assert set(EgressRecord.model_json_schema()["properties"]) == EXPECTED_PROPERTIES


# verify_link


def test_verify_link_failures() -> None:
    first = seal()
    second = seal(first)
    third = seal(second)
    with pytest.raises(ModelError, match="bad genesis"):
        second.verify_link(None)
    with pytest.raises(ModelError, match="sequence gap"):
        third.verify_link(first)
    other_first = seal(timestamp=T0 + timedelta(minutes=5), candidate_id=CAND_2)
    with pytest.raises(ModelError, match="previous hash mismatch"):
        second.verify_link(other_first)
    late_first = seal(timestamp=T0 + timedelta(hours=1))
    rebased = seal(late_first, timestamp=T0 + timedelta(minutes=1))
    with pytest.raises(ModelError, match="timestamp regression"):
        rebased.verify_link(late_first)


def test_scan_id_may_change_along_the_chain() -> None:
    first = seal()
    second = seal(first, scan_id="scan_01ARYZ6S41000000000000000Z")
    second.verify_link(first)


# properties

_hex = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


@st.composite
def records(draw: st.DrawFn) -> EgressRecord:
    outcome = draw(st.sampled_from([EgressOutcome.SENT, EgressOutcome.BLOCKED]))
    return seal(
        provider=draw(st.from_regex(r"[a-z][a-z0-9-]{0,20}", fullmatch=True)),
        model=draw(st.from_regex(r"[a-z0-9][a-z0-9.:-]{0,20}", fullmatch=True)),
        task=draw(st.none() | st.from_regex(r"[a-z][a-z0-9_-]{0,10}", fullmatch=True)),
        level=draw(st.sampled_from(PrivacyLevel)),
        payload_hash=draw(_hex),
        request_hash=draw(st.none() | _hex),
        token_counts=TokenCounts(prompt=draw(st.integers(0, 10**6))),
        outcome=outcome,
        block_code="size_budget" if outcome is EgressOutcome.BLOCKED else None,
        timestamp=T0 + timedelta(microseconds=draw(st.integers(0, 10**12))),
    )


@given(records(), st.data())
def test_round_trip_and_single_character_tamper(record: EgressRecord, data: st.DataObject) -> None:
    text = record.model_dump_json()
    assert EgressRecord.model_validate_json(text) == record
    hash_start = text.index(record.entry_hash)
    hash_range = range(hash_start, hash_start + 64)
    position = data.draw(st.integers(0, len(text) - 1).filter(lambda i: i not in hash_range))
    replacement = data.draw(st.sampled_from('0123456789abcdefXYZ:,{}_-."'))
    tampered = text[:position] + replacement + text[position + 1 :]
    if tampered == text:
        return
    try:
        json.loads(tampered)
    except json.JSONDecodeError:
        return
    try:
        reloaded = EgressRecord.model_validate_json(tampered)
    except ValidationError:
        return
    # An edit that still validates must not change the record's meaning.
    assert reloaded == record


@given(st.integers(1, 50), st.data())
def test_chains_verify_and_detect_edits(length: int, data: st.DataObject) -> None:
    chain = [seal()]
    for _ in range(length - 1):
        chain.append(seal(chain[-1]))
    previous: EgressRecord | None = None
    for record in chain:
        record.verify_link(previous)
        previous = record
    if length < 2:
        return
    edit = data.draw(st.sampled_from(["remove", "swap", "duplicate"]))
    index = data.draw(st.integers(0, length - 2))
    edited = chain[:]
    if edit == "remove":
        del edited[index]
    elif edit == "swap":
        edited[index], edited[index + 1] = edited[index + 1], edited[index]
    else:
        edited.insert(index, edited[index])
    with pytest.raises(ModelError):
        previous = None
        for record in edited:
            record.verify_link(previous)
            previous = record
