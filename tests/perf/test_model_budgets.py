"""Performance budgets of the core models (E02-31).

Budgets are roughly ten times the expected timings, to catch regressions and not noise. Each is
the best of three runs (``measure``), scaled by ``CODEKAVACH_PERF_FACTOR``. Input data is built
outside the timed region from the deterministic factories. The measured numbers are recorded in
docs/reference/domain-model.md ("Performance budgets").
"""

import re
import tracemalloc
from datetime import timedelta
from pathlib import Path

import pytest

from codekavach.core.models import (
    Candidate,
    EgressRecord,
    Evidence,
    Finding,
    FingerprintParts,
    Language,
    Location,
    PrivacyLevel,
    RawCode,
    SanitisedPayload,
    SanitisedText,
    ScanSummary,
    TaintPath,
    fingerprint_batch,
    snippet_hash,
    split_lines,
)
from tests.support import factories as f
from tests.support.perf import assert_within_budget, measure

SRC = Path(__file__).resolve().parents[2] / "src"
# Production uses of model_construct, each with the reason it cannot weaken validation.
MODEL_CONSTRUCT_ALLOWED = {
    "codekavach/core/models/egress.py": (
        "seal() builds an unvalidated draft only to compute entry_hash; the record it returns "
        "is created with model_validate, so every check runs"
    ),
}


def report(label: str, seconds: float, budget: float) -> None:
    print(f"{label}: {seconds:.3f} s (budget {budget} s)")  # noqa: T201 - recorded in the docs
    assert_within_budget(seconds, budget, label=label)


# --- unit tests (always run) ----------------------------------------------------------------


def test_budget_assertion_is_live() -> None:
    with pytest.raises(AssertionError, match=r"measured 1\.000 s; budget 3\.000 s x factor 0\.01"):
        assert_within_budget(1.0, 3.0, factor=0.01)
    assert_within_budget(1.0, 3.0, factor=1.0)


def test_no_production_model_construct() -> None:
    found = {
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*.py")
        if re.search(r"\bmodel_construct\(", path.read_text(encoding="utf-8"))
    }
    assert found <= set(MODEL_CONSTRUCT_ALLOWED), sorted(found - set(MODEL_CONSTRUCT_ALLOWED))
    assert all(reason.strip() for reason in MODEL_CONSTRUCT_ALLOWED.values())


# --- measurements (marker perf) -------------------------------------------------------------


def nine_line_finding(index: int) -> Finding:
    """A finding with one 9-line Evidence and a 3-step taint path."""
    location = f.make_location()
    # Lines 83 to 91: line 87 with four lines of context on each side (the file ends at 91).
    evidence = Evidence.from_source(
        RawCode(f.SAMPLE_FILE),
        f.make_location(start_line=87, end_line=87),
        language=Language.PYTHON,
        context_lines=4,
    )
    via = Location(path=f.SAMPLE_PATH, start_line=87, end_line=87)
    taint = TaintPath.from_locations(f.make_location(start_line=86, end_line=86), location, [via])
    return f.make_finding(evidence=(evidence,), taint_path=taint, title=f"SQL injection {index}")


@pytest.mark.perf
def test_construct_locations() -> None:
    paths = [f"./src\\bank//module_{index % 50}/accounts.py" for index in range(100_000)]

    def run() -> None:
        for index, path in enumerate(paths):
            Location(path=path, start_line=index % 500 + 1, end_line=index % 500 + 2)

    report("construct 100,000 Location", measure(run), 3.0)


@pytest.mark.perf
def test_validate_candidates() -> None:
    data = f.make_candidate().model_dump()

    def run() -> None:
        for _ in range(20_000):
            Candidate.model_validate(data)

    report("validate 20,000 Candidate", measure(run), 3.0)


@pytest.mark.perf
def test_finding_json_round_trip() -> None:
    finding = nine_line_finding(0)
    assert len(finding.evidence[0].lines) == 9
    assert finding.taint_path is not None
    assert len(finding.taint_path.steps) == 3

    def run() -> None:
        for _ in range(5_000):
            Finding.model_validate_json(finding.model_dump_json())

    report("JSON round trip of 5,000 Finding", measure(run), 5.0)


@pytest.mark.perf
def test_evidence_from_source() -> None:
    source = RawCode("".join(f"value_{n} = compute(value_{n - 1}) + {n}\n" for n in range(2_000)))
    locations = [
        Location(path="src/app.py", start_line=line, end_line=line, start_col=1, end_col=6)
        for line in range(1, 5_001)
        for line in [line % 1_990 + 5]
    ]

    def run() -> None:
        for location in locations:
            Evidence.from_source(source, location, language=Language.PYTHON)

    report("Evidence.from_source x 5,000", measure(run), 4.0)


@pytest.mark.perf
def test_fingerprint_batch() -> None:
    snippets = [[f"line {n} a", f"line {n} b", f"line {n} c"] for n in range(50_000)]

    def run() -> None:
        parts = [
            FingerprintParts(
                engine="codekavach-rules",
                rule_id="python.sqli.string-concat",
                path="src/bank/accounts.py",
                symbol="AccountRepo.find_by_owner",
                snippet_hash=snippet_hash(lines),
                start_line=index + 1,
            )
            for index, lines in enumerate(snippets)
        ]
        fingerprint_batch(parts)

    report("fingerprint_batch of 50,000", measure(run), 3.0)


@pytest.mark.perf
def test_seal_and_verify_chain() -> None:
    head = f.make_egress_chain(1)[0]

    def run() -> None:
        chain: list[EgressRecord] = []
        for index in range(20_000):
            chain.append(
                EgressRecord.seal(
                    prev=chain[-1] if chain else None,
                    timestamp=f.FIXED_NOW + timedelta(milliseconds=index),
                    scan_id=head.scan_id,
                    candidate_id=head.candidate_id,
                    provider="mock",
                    model="mock-1",
                    task="triage",
                    level=PrivacyLevel.L3,
                    payload_hash=head.payload_hash,
                    token_counts=head.token_counts,
                    outcome=head.outcome,
                )
            )
        previous = None
        for record in chain:
            record.verify_link(previous)
            previous = record

    report("seal and verify 20,000 EgressRecord", measure(run), 4.0)


@pytest.mark.perf
def test_split_lines() -> None:
    text = ("x" * 38 + "\r\n") * 50_000
    assert len(split_lines(text)) == 50_000
    report("split_lines of 50,000 CRLF lines", measure(lambda: split_lines(text)), 0.5)


@pytest.mark.perf
def test_scan_summary() -> None:
    findings = [f.make_finding()] * 5_000

    def run() -> None:
        ScanSummary.from_findings(
            findings,
            files_scanned=1,
            lines_scanned=1,
            candidates_total=5_000,
            candidates_reviewed_by_llm=0,
            egress=f.make_egress_totals(),
            duration_seconds=1.0,
        )

    report("ScanSummary.from_findings of 5,000", measure(run), 1.0)


@pytest.mark.perf
def test_build_payloads() -> None:
    placeholders = [f"<SECRET:aws_access_key:{n}>" for n in range(1, 6)]
    lines = [f"    var_{n} = fn_{n}(param_{n})" for n in range(55)] + [
        f"    key = {token}" for token in placeholders
    ]
    text = SanitisedText("\n".join(lines) + "\n")

    def run() -> None:
        for _ in range(5_000):
            SanitisedPayload.build(
                candidate_id=f.CANDIDATE_ID, slice_id=f.SLICE_ID, text=text, level=PrivacyLevel.L3
            )

    report("SanitisedPayload.build x 5,000", measure(run), 4.0)


@pytest.mark.perf
def test_memory_of_five_thousand_findings() -> None:
    tracemalloc.start()
    try:
        findings = [nine_line_finding(index) for index in range(5_000)]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(findings) == 5_000
    print(f"peak traced memory for 5,000 findings: {peak / 1e6:.0f} MB")  # noqa: T201
    assert peak < 400 * 1024 * 1024
