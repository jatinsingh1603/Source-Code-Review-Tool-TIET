import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import (
    Confidence,
    DataClassification,
    FindingStatus,
    InvalidStatusTransition,
    Language,
    PrivacyLevel,
    Severity,
)
from codekavach.core.models.enums import ActorKind, DetectionOrigin
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import (
    EngineRef,
    Finding,
    Impact,
    Likelihood,
    LLMReviewRef,
    Provenance,
)
from codekavach.core.models.lifecycle import StatusChange
from codekavach.core.models.location import Location
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.taxonomy import Reference, TaxonomyRef
from codekavach.core.models.text import RawCode
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).parent / "golden" / "finding_v1.json"
CREATED = datetime(2026, 10, 5, 4, 30, tzinfo=UTC)
SCAN_ID = "scan_01ARYZ6S410000000000000000"
CANDIDATE_ID = "cand_01ARYZ6S410000000000000001"
FINDING_ID = "find_01ARYZ6S410000000000000002"
SINK = Location(
    path="src/bank/accounts.py", start_line=88, end_line=88, symbol="AccountRepo.find_by_owner"
)
SOURCE_TEXT = RawCode(  # deliberately vulnerable sample code
    "\n".join(  # noqa: S608 - sample of the SQL injection under test
        [f"# line {n}" for n in range(1, 86)]
        + [
            "    def find_by_owner(self, owner):",
            "        cur = self.conn.cursor()",
            '        cur.execute("SELECT * FROM accounts WHERE owner = \'" + owner + "\'")',
            "        return cur.fetchall()",
        ]
    )
    + "\n"
)


def provenance(**overrides: Any) -> Provenance:
    fields: dict[str, Any] = {
        "origin": DetectionOrigin.DETERMINISTIC,
        "scan_id": SCAN_ID,
        "candidate_ids": (CANDIDATE_ID,),
        "engines": (EngineRef(engine="codekavach-rules", rule_id="python.sqli.string-concat"),),
        "llm_reviews": (
            LLMReviewRef(
                provider="mock",
                model="mock-1",
                task="triage",
                level=PrivacyLevel.L3,
                ledger_seq=0,
                is_vulnerable=True,
                confidence=Confidence.HIGH,
                reasoning="owner flows into cur.execute through string concatenation.",
            ),
        ),
        "codekavach_version": "0.1.0.dev0",
    }
    fields.update(overrides)
    return Provenance.model_validate(fields)


def example(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "id": FINDING_ID,
        "title": "SQL injection in AccountRepo.find_by_owner",
        "severity": Severity.HIGH,
        "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "cvss4_score": 9.3,
        "cwe": (89,),
        "owasp": (TaxonomyRef(scheme="owasp-top10", id="A03", title="Injection", version="2021"),),
        "compliance": (TaxonomyRef(scheme="pci-dss", id="6.2.4", version="4.0"),),
        "locations": (SINK,),
        "evidence": (
            Evidence.from_source(SOURCE_TEXT, SINK, language=Language.PYTHON, context_lines=2),
        ),
        "impact": Impact(level=4, narrative="An attacker can read every account row."),
        "likelihood": Likelihood(level=4, rationale="The owner parameter comes from a request."),
        "remediation": "Use a parameterised query.",
        "references": (
            Reference(title="CWE-89", url="https://cwe.mitre.org/data/definitions/89.html"),
        ),
        "provenance": provenance(),
        "fingerprint": "ckfp1:58d192700c1c56f2f97f4e2ae1ec20ee",
        "correlation_key": "ckck1:53fd354cc11c0db1b4ba659bb73d4189",
        "confidence": Confidence.HIGH,
        "description": "The query string is built by concatenating the owner parameter.",
        "taint_path": TaintPath.from_locations(
            Location(path="src/bank/views.py", start_line=12, end_line=12, symbol="statement"),
            SINK,
        ),
        "language": Language.PYTHON,
        "created_at": CREATED,
    }
    fields.update(overrides)
    return fields


def make(**overrides: Any) -> Finding:
    return Finding.model_validate(example(**overrides))


def test_example_round_trips() -> None:
    finding = make()
    assert Finding.model_validate_json(finding.model_dump_json()) == finding
    assert finding.primary_location == SINK
    assert finding.primary_cwe == 89


def test_golden_file() -> None:
    assert_matches_golden(make().model_dump_json(indent=2) + "\n", GOLDEN)


def test_classification() -> None:
    for model in (Finding, Provenance, EngineRef, LLMReviewRef, Impact, Likelihood):
        assert model.DATA_CLASSIFICATION is DataClassification.RAW
    for metadata_model in (TaxonomyRef, Reference):
        assert metadata_model.DATA_CLASSIFICATION is DataClassification.METADATA


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"locations": ()}, "at least 1"),
        ({"fingerprint": "ckfp1:XYZ"}, "pattern"),
        ({"cvss4_score": None}, "both be set"),
        ({"cvss4_score": 10.5}, "less than or equal"),
        ({"cvss4_score": 7.25}, "one decimal"),
        ({"cvss4_vector": "CVSS:3.1/AV:N"}, "CVSS:4.0"),
        ({"title": "two\nlines"}, "single line"),
        ({"correlation_key": "ckck1:nothex"}, "pattern"),
    ],
)
def test_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        make(**overrides)


def test_history_must_end_in_status() -> None:
    change = StatusChange(
        from_status=FindingStatus.OPEN,
        to_status=FindingStatus.CONFIRMED,
        at=CREATED,
        actor_kind=ActorKind.HUMAN,
        actor="alice",
    )
    with pytest.raises(ValidationError, match="current status"):
        make(status_history=(change,))
    assert make(status=FindingStatus.CONFIRMED, status_history=(change,)).status_history


def test_history_must_chain() -> None:
    first = StatusChange(
        from_status=FindingStatus.OPEN,
        to_status=FindingStatus.CONFIRMED,
        at=CREATED,
        actor_kind=ActorKind.HUMAN,
        actor="alice",
    )
    broken = first.evolve(from_status=FindingStatus.FIXED, to_status=FindingStatus.OPEN)
    with pytest.raises(ValidationError, match="chain"):
        make(status=FindingStatus.OPEN, status_history=(first, broken))


def test_deterministic_origin_needs_engines() -> None:
    with pytest.raises(ValidationError, match="deterministic"):
        provenance(engines=())
    assert provenance(origin=DetectionOrigin.LLM, engines=()).engines == ()


def test_evidence_must_match_locations() -> None:
    other = Location(path="src/bank/other.py", start_line=1, end_line=1)
    stray = Evidence.from_source(RawCode("x = 1\n"), other, language=Language.PYTHON)
    with pytest.raises(ValidationError, match="evidence"):
        make(evidence=(stray,))


def test_reference_url_scheme() -> None:
    with pytest.raises(ValidationError, match="http"):
        Reference(title="x", url="javascript:alert(1)")
    assert Reference(title="x", url="http://example.test/").url


def test_taxonomy_scheme() -> None:
    with pytest.raises(ValidationError):
        TaxonomyRef(scheme="OWASP", id="A03")


def test_with_status() -> None:
    finding = make()
    change = StatusChange(
        from_status=FindingStatus.OPEN,
        to_status=FindingStatus.CONFIRMED,
        at=CREATED + timedelta(hours=1),
        actor_kind=ActorKind.HUMAN,
        actor="alice",
    )
    confirmed = finding.with_status(change)
    assert confirmed.status is FindingStatus.CONFIRMED
    assert confirmed.status_history == (change,)
    assert finding.status is FindingStatus.OPEN
    assert finding.status_history == ()
    illegal = change.evolve(from_status=FindingStatus.CONFIRMED, to_status=FindingStatus.CONFIRMED)
    with pytest.raises(InvalidStatusTransition):
        confirmed.with_status(illegal)


def test_sort_key_ordering() -> None:
    def variant(severity: Severity, confidence: Confidence, path: str, line: int) -> Finding:
        location = Location(path=path, start_line=line, end_line=line)
        return make(
            severity=severity,
            confidence=confidence,
            locations=(location,),
            evidence=(),
            taint_path=None,
        )

    expected = [
        variant(Severity.CRITICAL, Confidence.LOW, "z.py", 1),
        variant(Severity.HIGH, Confidence.HIGH, "b.py", 9),
        variant(Severity.HIGH, Confidence.MEDIUM, "a.py", 1),
        variant(Severity.HIGH, Confidence.MEDIUM, "a.py", 5),
        variant(Severity.LOW, Confidence.HIGH, "a.py", 1),
    ]
    shuffled = expected[:]
    random.Random(4).shuffle(shuffled)  # noqa: S311 - seeded test shuffle
    assert sorted(shuffled, key=Finding.sort_key) == expected


@given(
    st.sampled_from(Severity),
    st.sampled_from(Confidence),
    st.sampled_from(FindingStatus),
    st.integers(1, 5),
    st.integers(0, 100).map(lambda n: n / 10),
)
def test_round_trip_smoke(
    severity: Severity, confidence: Confidence, status: FindingStatus, level: int, score: float
) -> None:
    finding = make(
        severity=severity,
        confidence=confidence,
        status=status,
        impact=Impact(level=level),
        likelihood=Likelihood(level=level),
        cvss4_score=score,
    )
    assert Finding.model_validate_json(finding.model_dump_json()) == finding
