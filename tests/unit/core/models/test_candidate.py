import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from codekavach.core.models import DataClassification, Language, Severity, TaintRole
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.ids import is_ulid, strip_prefix
from codekavach.core.models.location import Location
from codekavach.core.models.taint import TaintPath
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).parent / "golden" / "candidate_v1.json"
FIXED_ID = "cand_01ARYZ6S410000000000000000"
PRIMARY = Location(
    path="src/bank/accounts.py", start_line=88, end_line=88, symbol="AccountRepo.find_by_owner"
)


def example(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "rule_id": "python.sqli.string-concat",
        "engine": "codekavach-rules",
        "cwe": ("CWE-89",),
        "locations": (PRIMARY,),
        "engine_severity": Severity.HIGH,
        "fingerprint": "ckfp1:58d192700c1c56f2f97f4e2ae1ec20ee",
        "language": Language.PYTHON,
        "message": "SQL query built by string concatenation",
    }
    fields.update(overrides)
    return fields


def test_example_validates() -> None:
    candidate = Candidate.create(**example())
    assert candidate.cwe == (89,)
    assert candidate.schema_version == 1
    assert candidate.DATA_CLASSIFICATION is DataClassification.RAW


def test_create_generates_or_keeps_id() -> None:
    generated = Candidate.create(**example())
    assert generated.id.startswith("cand_")
    assert is_ulid(strip_prefix(generated.id))
    assert Candidate.create(**example(id=FIXED_ID)).id == FIXED_ID


def test_json_round_trip() -> None:
    candidate = Candidate.create(**example())
    assert json.loads(candidate.model_dump_json())["schema_version"] == 1
    assert Candidate.model_validate_json(candidate.model_dump_json()) == candidate


def test_golden_file() -> None:
    candidate = Candidate.create(**example(id=FIXED_ID))
    assert_matches_golden(candidate.model_dump_json(indent=2) + "\n", GOLDEN)


def test_empty_locations_rejected() -> None:
    with pytest.raises(ValidationError):
        Candidate.create(**example(locations=()))


@pytest.mark.parametrize("engine", ["Semgrep", "sem grep", "", "-x", "a" * 65])
def test_invalid_engine_rejected(engine: str) -> None:
    with pytest.raises(ValidationError, match="engine"):
        Candidate.create(**example(engine=engine))


@pytest.mark.parametrize("rule_id", ["a\nb", "a b", "a\x00", ""])
def test_invalid_rule_id_rejected(rule_id: str) -> None:
    with pytest.raises(ValidationError):
        Candidate.create(**example(rule_id=rule_id))


def test_rule_id_keeps_case() -> None:
    assert Candidate.create(**example(rule_id="java/SQL-Injection")).rule_id == "java/SQL-Injection"


@pytest.mark.parametrize(
    "fingerprint", ["ckfp1:58D192700C1C56F2F97F4E2AE1EC20EE", "ckfp2:" + "0" * 32, "0" * 32]
)
def test_invalid_fingerprint_rejected(fingerprint: str) -> None:
    with pytest.raises(ValidationError):
        Candidate.create(**example(fingerprint=fingerprint))


def test_duplicate_property_keys_rejected() -> None:
    with pytest.raises(ValidationError, match="unique"):
        Candidate.create(**example(properties=(("a", "1"), ("a", "2"))))


def test_too_many_properties_rejected() -> None:
    props = tuple((f"k{i}", "v") for i in range(33))
    with pytest.raises(ValidationError):
        Candidate.create(**example(properties=props))
    assert len(Candidate.create(**example(properties=props[:32])).properties) == 32


def test_invalid_property_key_and_value_rejected() -> None:
    with pytest.raises(ValidationError, match="keys"):
        Candidate.create(**example(properties=(("Bad", "1"),)))
    with pytest.raises(ValidationError, match="500"):
        Candidate.create(**example(properties=(("k", "x" * 501),)))


def test_message_length() -> None:
    with pytest.raises(ValidationError):
        Candidate.create(**example(message="x" * 2001))


def _path(sink_file: str) -> TaintPath:
    return TaintPath.from_locations(
        Location(path="src/bank/views.py", start_line=3, end_line=3),
        Location(path=sink_file, start_line=88, end_line=88),
    )


def test_taint_sink_must_be_among_locations() -> None:
    with pytest.raises(ValidationError, match="sink file"):
        Candidate.create(**example(taint_path=_path("src/bank/other.py")))
    ok = Candidate.create(**example(taint_path=_path("src/bank/accounts.py")))
    assert ok.taint_path is not None
    assert ok.taint_path.sink.role is TaintRole.SINK


def test_cwe_deduplication_keeps_order() -> None:
    assert Candidate.create(**example(cwe=("CWE-89", 89, "CWE-564"))).cwe == (89, 564)


def test_properties_helpers() -> None:
    second = Location(path="src/bank/util.py", start_line=1, end_line=1)
    candidate = Candidate.create(
        **example(locations=(PRIMARY, second), taint_path=_path("src/bank/accounts.py"))
    )
    assert candidate.primary_location == PRIMARY
    assert candidate.primary_cwe == 89
    assert candidate.files == ("src/bank/accounts.py", "src/bank/util.py", "src/bank/views.py")
    assert Candidate.create(**example(cwe=())).primary_cwe is None
