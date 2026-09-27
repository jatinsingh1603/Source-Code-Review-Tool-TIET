import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import (
    Confidence,
    DataClassification,
    FindingStatus,
    Language,
    PrivacyLevel,
    Severity,
)
from codekavach.core.models.egress import EgressRecord, TokenCounts
from codekavach.core.models.enums import DetectionOrigin, EgressOutcome
from codekavach.core.models.finding import EngineRef, Finding, Impact, Likelihood, Provenance
from codekavach.core.models.ids import CandidateId, FindingId, ScanId
from codekavach.core.models.location import Location
from codekavach.core.models.summary import EgressTotals, ScanSummary

T0 = datetime(2026, 10, 5, tzinfo=UTC)
SCAN = "scan_01ARYZ6S410000000000000000"
PROVENANCE = Provenance(
    origin=DetectionOrigin.DETERMINISTIC,
    scan_id=ScanId(SCAN),
    candidate_ids=(CandidateId("cand_01ARYZ6S410000000000000001"),),
    engines=(EngineRef(engine="codekavach-rules", rule_id="r1"),),
    codekavach_version="0.1.0.dev0",
)


def finding(
    n: int,
    severity: Severity,
    *,
    cwe: tuple[int, ...] = (89,),
    language: Language = Language.PYTHON,
    status: FindingStatus = FindingStatus.OPEN,
    likelihood: int = 3,
    impact: int = 3,
) -> Finding:
    return Finding(
        id=FindingId(f"find_01ARYZ6S4100000000000000{n:02d}"),
        title=f"finding {n}",
        severity=severity,
        cwe=cwe,
        locations=(Location(path=f"src/f{n}.py", start_line=1, end_line=1),),
        impact=Impact(level=impact),
        likelihood=Likelihood(level=likelihood),
        provenance=PROVENANCE,
        fingerprint="ckfp1:" + f"{n:032x}",
        confidence=Confidence.MEDIUM,
        language=language,
        status=status,
        created_at=T0,
    )


FP = FindingStatus.FALSE_POSITIVE
SUPPRESSED = FindingStatus.SUPPRESSED


def twelve() -> list[Finding]:
    s = Severity
    return [
        finding(1, s.CRITICAL, cwe=(89,), likelihood=5, impact=5),
        finding(2, s.HIGH, cwe=(79,), language=Language.JAVASCRIPT, likelihood=4, impact=4),
        finding(3, s.HIGH, cwe=(89,), likelihood=4, impact=4),
        finding(4, s.MEDIUM, cwe=(22,), language=Language.JAVA),
        finding(5, s.MEDIUM, cwe=(79,), language=Language.JAVASCRIPT),
        finding(6, s.MEDIUM, cwe=(798,), status=FindingStatus.CONFIRMED),
        finding(7, s.LOW, cwe=(), language=Language.GO, likelihood=2, impact=1),
        finding(8, s.LOW, cwe=(22,), language=Language.JAVA, likelihood=2, impact=1),
        finding(
            9, s.INFO, cwe=(1004,), status=FindingStatus.FALSE_POSITIVE, likelihood=1, impact=1
        ),
        finding(10, s.HIGH, cwe=(89,), status=FindingStatus.FIXED, likelihood=4, impact=4),
        finding(11, s.MEDIUM, cwe=(352,), language=Language.GO),
        finding(
            12, s.LOW, cwe=(79,), language=Language.JAVASCRIPT, status=FindingStatus.SUPPRESSED
        ),
    ]


def summarise(findings: list[Finding], **overrides: Any) -> ScanSummary:
    fields: dict[str, Any] = {
        "files_scanned": 40,
        "lines_scanned": 5000,
        "candidates_total": 30,
        "candidates_reviewed_by_llm": 12,
        "egress": EgressTotals.empty(),
        "duration_seconds": 12.5,
    }
    fields.update(overrides)
    return ScanSummary.from_findings(findings, **fields)


def test_twelve_findings() -> None:
    summary = summarise(twelve())
    assert summary.findings_total == 12
    assert [(s.value, n) for s, n in summary.by_severity] == [
        ("critical", 1),
        ("high", 3),
        ("medium", 4),
        ("low", 3),
        ("info", 1),
    ]
    assert dict(summary.by_status) == {
        FindingStatus.OPEN: 8,
        FindingStatus.CONFIRMED: 1,
        FindingStatus.FALSE_POSITIVE: 1,
        FindingStatus.ACCEPTED_RISK: 0,
        FindingStatus.SUPPRESSED: 1,
        FindingStatus.FIXED: 1,
    }
    assert summary.top_cwes == ((79, 3), (89, 3), (22, 2), (352, 1), (798, 1), (1004, 1))
    assert summary.by_language == (
        (Language.PYTHON, 5),
        (Language.JAVASCRIPT, 3),
        (Language.GO, 2),
        (Language.JAVA, 2),
    )
    assert summary.risk_matrix == ((1, 1, 1), (2, 1, 2), (3, 3, 5), (4, 4, 3), (5, 5, 1))
    assert summary.count(Severity.HIGH) == 3
    assert summary.highest_severity is Severity.CRITICAL
    rng = random.Random(7)  # noqa: S311 - seeded test shuffle
    for _ in range(50):
        shuffled = twelve()
        rng.shuffle(shuffled)
        assert summarise(shuffled) == summary


def test_empty_summary() -> None:
    summary = summarise([])
    assert summary.findings_total == 0
    assert [s for s, _ in summary.by_severity] == list(Severity)[::-1]
    assert summary.highest_severity is None
    assert ScanSummary.model_validate_json(summary.model_dump_json()) == summary


def test_json_pairs_are_arrays() -> None:
    data = summarise(twelve()).model_dump(mode="json")
    assert data["by_severity"][0] == ["critical", 1]


def valid_fields(**overrides: Any) -> dict[str, Any]:
    data = summarise(twelve()).model_dump()
    data.update(overrides)
    return data


FOUR_SEVERITIES = (
    (Severity.CRITICAL, 1),
    (Severity.HIGH, 3),
    (Severity.MEDIUM, 4),
    (Severity.LOW, 4),
)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"findings_total": 13}, "findings_total"),
        (
            {
                "by_severity": (
                    (Severity.CRITICAL, 1),
                    (Severity.HIGH, 3),
                    (Severity.MEDIUM, 4),
                    (Severity.LOW, 4),
                )
            },
            "five",
        ),
        ({"risk_matrix": ((6, 1, 12),)}, "between 1 and 5"),
        ({"risk_matrix": ((1, 1, 6), (1, 1, 6))}, "repeated"),
        ({"candidates_reviewed_by_llm": 31}, "reviewed"),
        ({"duration_seconds": -1.0}, "greater than or equal"),
        ({"duration_seconds": float("inf")}, "finite"),
    ],
    ids=["total", "four-severities", "level-6", "repeated-cell", "reviewed", "negative", "inf"],
)
def test_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        ScanSummary.model_validate(valid_fields(**overrides))


def test_classification() -> None:
    assert ScanSummary.DATA_CLASSIFICATION is DataClassification.METADATA
    assert EgressTotals.DATA_CLASSIFICATION is DataClassification.METADATA


# egress totals


def record(prev: EgressRecord | None, outcome: EgressOutcome, **overrides: Any) -> EgressRecord:
    fields: dict[str, Any] = {
        "prev": prev,
        "timestamp": T0 + timedelta(seconds=0 if prev is None else prev.seq),
        "scan_id": SCAN,
        "candidate_id": "cand_01ARYZ6S410000000000000001",
        "provider": "mock",
        "model": "mock-1",
        "task": "triage",
        "level": PrivacyLevel.L3,
        "payload_hash": "a" * 64,
        "token_counts": TokenCounts(prompt=100),
        "outcome": outcome,
    }
    if outcome is EgressOutcome.BLOCKED:
        fields["block_code"] = "residual_secret"
    fields.update(overrides)
    return EgressRecord.seal(**fields)


def chain() -> list[EgressRecord]:
    first = record(None, EgressOutcome.SENT, token_counts=TokenCounts(prompt=120))
    done = record(
        first,
        EgressOutcome.COMPLETED,
        ref_seq=1,
        token_counts=TokenCounts(prompt=118, completion=64, estimated=False),
    )
    blocked = record(done, EgressOutcome.BLOCKED)
    second = record(
        blocked, EgressOutcome.SENT, level=PrivacyLevel.L2, token_counts=TokenCounts(prompt=90)
    )
    failed = record(second, EgressOutcome.FAILED, ref_seq=4)
    return [first, done, blocked, second, failed]


def test_from_records() -> None:
    totals = EgressTotals.from_records(chain())
    assert totals.requests_sent == 2
    assert totals.requests_blocked == 1
    assert totals.requests_failed == 1
    assert totals.prompt_tokens == 118 + 90
    assert totals.completion_tokens == 64
    assert totals.tokens_estimated is True
    assert dict(totals.levels) == {
        PrivacyLevel.L1: 0,
        PrivacyLevel.L2: 1,
        PrivacyLevel.L3: 1,
        PrivacyLevel.L4: 0,
        PrivacyLevel.L0: 0,
    }
    assert EgressTotals.model_validate_json(totals.model_dump_json()) == totals


def test_empty_totals() -> None:
    empty = EgressTotals.empty()
    assert empty.requests_sent == 0
    assert [level for level, _ in empty.levels] == sorted(PrivacyLevel)
    assert EgressTotals.from_records([]) == empty


def test_levels_must_be_complete_and_consistent() -> None:
    data = EgressTotals.from_records(chain()).model_dump()
    with pytest.raises(ValidationError, match="five privacy levels"):
        EgressTotals.model_validate({**data, "levels": data["levels"][:4]})
    with pytest.raises(ValidationError, match="requests_sent"):
        EgressTotals.model_validate({**data, "requests_sent": 3})


# properties


@given(
    st.lists(
        st.tuples(
            st.sampled_from(Severity),
            st.sampled_from(FindingStatus),
            st.sampled_from([Language.PYTHON, Language.GO, Language.JAVA]),
            st.integers(1, 5),
            st.integers(1, 5),
            st.sampled_from([(), (89,), (79,), (22,)]),
        ),
        max_size=25,
    ),
    st.randoms(),
)
def test_from_findings_is_permutation_invariant(
    specs: list[tuple[Severity, FindingStatus, Language, int, int, tuple[int, ...]]],
    rng: random.Random,
) -> None:
    findings = [
        finding(i, sev, status=stat, language=lang, likelihood=lik, impact=imp, cwe=cwe)
        for i, (sev, stat, lang, lik, imp, cwe) in enumerate(specs)
    ]
    summary = summarise(findings)
    shuffled = findings[:]
    rng.shuffle(shuffled)
    assert summarise(shuffled) == summary
    assert summary.findings_total == sum(n for _, n in summary.by_severity)
    assert summary.findings_total == sum(n for _, n in summary.by_status)
    assert summary.findings_total == sum(n for _, _, n in summary.risk_matrix)


@given(st.lists(st.sampled_from(["sent", "blocked", "follow"]), max_size=20), st.randoms())
def test_from_records_is_permutation_invariant(steps: list[str], rng: random.Random) -> None:
    records: list[EgressRecord] = []
    open_sent: list[int] = []
    for step in steps:
        prev = records[-1] if records else None
        if step == "follow" and open_sent:
            ref = open_sent.pop()
            records.append(record(prev, EgressOutcome.COMPLETED, ref_seq=ref))
        elif step == "blocked":
            records.append(record(prev, EgressOutcome.BLOCKED))
        else:
            records.append(record(prev, EgressOutcome.SENT))
            open_sent.append(records[-1].seq)
    totals = EgressTotals.from_records(records)
    shuffled = records[:]
    rng.shuffle(shuffled)
    assert EgressTotals.from_records(shuffled) == totals
    without_ref = sum(1 for r in records if r.ref_seq is None)
    assert totals.requests_sent + totals.requests_blocked == without_ref
