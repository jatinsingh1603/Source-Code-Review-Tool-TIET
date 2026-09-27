from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from codekavach.core.models import Severity
from codekavach.core.models.ids import decode_ulid, encode_ulid
from codekavach.core.models.text import SanitisedText
from tests.support import factories
from tests.support.factories import (
    FIXED_NOW_MS,
    fixed_ids,
    make_candidate,
    make_egress_chain,
    make_egress_totals,
    make_evidence,
    make_finding,
    make_location,
    make_payload,
    make_project,
    make_region,
    make_scan,
    make_slice,
    make_summary,
    make_taint_path,
    make_verdict,
)

SUPPORT_DIR = Path(factories.__file__).parent
# pragma: allowlist nextline secret
VECTOR_HASH = "5f8580ae81d45f1645ff37a6bb8d2272e1952e2a277bb703ff164184eeaad992"

FACTORIES: list[Callable[..., BaseModel]] = [
    make_location,
    make_region,
    make_taint_path,
    make_candidate,
    make_slice,
    make_payload,
    make_verdict,
    make_evidence,
    make_finding,
    make_egress_totals,
    make_summary,
    make_project,
    make_scan,
]


@pytest.mark.parametrize("factory", FACTORIES, ids=lambda f: f.__name__)
def test_factory_is_valid_and_deterministic(factory: Callable[..., BaseModel]) -> None:
    first, second = factory(), factory()
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert type(first).model_validate_json(first.model_dump_json()) == first


def test_override_replaces_exactly_one_field() -> None:
    base = make_finding()
    low = make_finding(severity=Severity.LOW)
    assert low.severity is Severity.LOW
    changed = {k for k in type(base).model_fields if getattr(base, k) != getattr(low, k)}
    assert changed == {"severity"}


def test_invalid_override_raises() -> None:
    with pytest.raises(ValidationError):
        make_location(start_line=0)


def test_payload_override_recomputes_hash() -> None:
    changed = make_payload(text=SanitisedText("v_1 = 1\n"), line_map=())
    assert changed.payload_hash != make_payload().payload_hash
    assert changed.id == make_payload().id


def test_egress_chain() -> None:
    chain = make_egress_chain(5)
    assert len(chain) == 5
    assert chain[0].entry_hash == VECTOR_HASH
    previous = None
    for record in chain:
        record.verify_link(previous)
        previous = record


def test_candidate_fingerprint_is_vector_a() -> None:
    assert make_candidate().fingerprint == "ckfp1:58d192700c1c56f2f97f4e2ae1ec20ee"


def test_fixed_ids() -> None:
    first = [fixed_ids().new() for _ in range(3)]
    assert len(set(first)) == 1
    factory = fixed_ids()
    sequence = [factory.new() for _ in range(5)]
    again = fixed_ids()
    assert [again.new() for _ in range(5)] == sequence
    assert sequence[0] == encode_ulid(FIXED_NOW_MS, bytes(10))
    assert sequence[0].startswith("01")
    assert sequence[0].endswith("0" * 16)
    assert decode_ulid(sequence[0])[0] == FIXED_NOW_MS


def test_cross_object_coherence() -> None:
    candidate = make_candidate()
    code_slice = make_slice()
    assert code_slice.candidate_id == candidate.id
    assert make_payload().slice_id == code_slice.id
    assert make_payload().candidate_id == candidate.id
    assert make_evidence().location == candidate.primary_location
    assert make_finding().fingerprint == candidate.fingerprint
    assert make_egress_chain(1)[0].candidate_id == candidate.id
    assert make_scan().id == make_finding().provenance.scan_id


def test_no_secret_literals_outside_synthetic() -> None:
    markers = ("AK" + "IA", "gh" + "p_", "s" + "k-", "-----BEG" + "IN")
    offenders: list[tuple[str, str]] = []
    for path in SUPPORT_DIR.glob("*.py"):
        if path.name == "synthetic.py":
            continue
        text = path.read_text(encoding="utf-8")
        offenders.extend((path.name, marker) for marker in markers if marker in text)
    assert offenders == []
