"""Serialisation round-trip and invariant properties P1 to P8 for every exported model (E02-27)."""

from datetime import UTC, datetime
from typing import Annotated, Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from pydantic import AwareDatetime, PlainSerializer

from codekavach.core import models
from codekavach.core.models import (
    ContextRequest,
    EngineRef,
    FingerprintParts,
    HighlightRange,
    Impact,
    Likelihood,
    LineMapEntry,
    LLMReviewRef,
    PlaceholderRef,
    Provenance,
    Reference,
    SnippetLine,
    StageResult,
    StatusChange,
    Stub,
    TaintStep,
    TaxonomyRef,
    TokenCounts,
)
from codekavach.core.models.base import KavachModel, VersionedModel
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.egress import EgressRecord
from codekavach.core.models.enums import Language, PrivacyLevel, ScanStatus, SegmentRole
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.export import EXPORTED_MODELS
from codekavach.core.models.finding import Finding
from codekavach.core.models.location import CodeRegion, Location
from codekavach.core.models.payload import SanitisedPayload
from codekavach.core.models.scan import Project, Scan
from codekavach.core.models.slice import CodeSlice, SliceSegment
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.text import RawCode, SanitisedText
from codekavach.core.models.verdict import LLMVerdict
from tests.support import factories as f
from tests.support import strategies as s
from tests.support.model_properties import (
    check_all,
    check_p3,
    check_p6,
    check_p7,
    check_p8,
)

MODEL_STRATEGIES: dict[type[KavachModel], SearchStrategy[Any]] = {
    Location: s.locations(),
    CodeRegion: s.regions(),
    TaintPath: s.taint_paths(),
    Candidate: s.candidates(),
    CodeSlice: s.code_slices(),
    SanitisedPayload: s.sanitised_payloads(),
    LLMVerdict: s.verdicts(),
    Evidence: s.evidences(),
    Finding: s.findings(),
    EgressRecord: s.egress_chains(max_size=5).map(lambda chain: chain[-1]),
    Project: s.projects(),
    Scan: s.scans(),
    ScanSummary: s.summaries(),
    EgressTotals: s.egress_totals(),
    # Component models, drawn from the strategy of the document that contains them.
    TaintStep: s.taint_paths().map(lambda path: path.steps[0]),
    SnippetLine: s.evidences().map(lambda evidence: evidence.lines[0]),
    HighlightRange: s.evidences()
    .filter(lambda evidence: evidence.highlights)
    .map(lambda evidence: evidence.highlights[0]),
    SliceSegment: s.code_slices().map(lambda code_slice: code_slice.segments[0]),
    LineMapEntry: s.sanitised_payloads()
    .filter(lambda payload: payload.line_map)
    .map(lambda payload: payload.line_map[0]),
    PlaceholderRef: s.sanitised_payloads()
    .filter(lambda payload: payload.placeholders)
    .map(lambda payload: payload.placeholders[0]),
    ContextRequest: s.verdicts()
    .filter(lambda verdict: verdict.needs_context)
    .map(lambda verdict: verdict.needs_context[0]),
    TokenCounts: s.egress_chains(max_size=3).map(lambda chain: chain[0].token_counts),
    StatusChange: s.status_histories().filter(lambda pair: pair[1]).map(lambda pair: pair[1][-1]),
    Impact: s.findings().map(lambda finding: finding.impact),
    Likelihood: s.findings().map(lambda finding: finding.likelihood),
    Provenance: s.findings().map(lambda finding: finding.provenance),
    EngineRef: s.findings()
    .filter(lambda finding: finding.provenance.engines)
    .map(lambda finding: finding.provenance.engines[0]),
    LLMReviewRef: s.findings()
    .filter(lambda finding: finding.provenance.llm_reviews)
    .map(lambda finding: finding.provenance.llm_reviews[0]),
    TaxonomyRef: s.findings()
    .filter(lambda finding: finding.owasp)
    .map(lambda finding: finding.owasp[0]),
    Reference: s.findings()
    .filter(lambda finding: finding.references)
    .map(lambda finding: finding.references[0]),
}
EXEMPT: dict[type[KavachModel], str] = {
    KavachModel: "abstract base class; covered through every concrete model",
    VersionedModel: "abstract base class; covered through every versioned model",
    FingerprintParts: "input value object of compute_fingerprint; never persisted or exchanged",
    Stub: "no strategy produces stubs yet; the slicer (E10) adds them with its own strategy",
    StageResult: "only reachable through the slow scans() strategy; covered by the Scan round trip",
}
# Documents that embed several findings get a smaller share of the budget.
FINDING_PARTS = (Impact, Likelihood, Provenance, EngineRef, LLMReviewRef, TaxonomyRef, Reference)
MAX_EXAMPLES = {Scan: 60, ScanSummary: 60, Finding: 120, **dict.fromkeys(FINDING_PARTS, 60)}


@pytest.mark.parametrize("model", list(MODEL_STRATEGIES), ids=lambda model: model.__name__)
def test_properties(model: type[KavachModel]) -> None:
    budget = min(settings().max_examples, MAX_EXAMPLES.get(model, 200))

    @settings(max_examples=budget, deadline=None)
    @given(MODEL_STRATEGIES[model])
    def run(instance: KavachModel) -> None:
        check_all(model, instance)

    run()


def test_every_exported_model_is_covered() -> None:
    exported = {
        value
        for name in models.__all__
        if isinstance(value := getattr(models, name), type) and issubclass(value, KavachModel)
    }
    exported |= set(EXPORTED_MODELS)
    missing = exported - set(MODEL_STRATEGIES) - set(EXEMPT)
    assert not missing, f"models without a strategy: {sorted(m.__name__ for m in missing)}"
    assert all(reason.strip() for reason in EXEMPT.values())
    assert not set(EXEMPT) & set(MODEL_STRATEGIES)


# --- pinned edge cases: exercised on every run, whatever hypothesis draws -------------------

ZERO_US = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
MAX_US = datetime(2026, 1, 2, 3, 4, 5, 999_999, tzinfo=UTC)
NON_ASCII_PATH = "src/données/खाता सेवा/naïve.py"
AWKWARD_LINES = (
    "crlf line",
    "lone" + chr(13) + "carriage",
    "form" + chr(12) + "feed",
    "line" + chr(0x2028) + "separator",
)


def _awkward_slice() -> CodeSlice:
    text = "\r\n".join(AWKWARD_LINES)  # no trailing newline
    segment = SliceSegment(
        path=NON_ASCII_PATH,
        region=CodeRegion(start_line=1, end_line=len(AWKWARD_LINES)),
        text=RawCode(text),
        role=SegmentRole.PRIMARY,
    )
    return f.make_slice(segments=(segment,))


def _awkward_evidence() -> Evidence:
    source = RawCode("\r\n".join(AWKWARD_LINES))
    location = Location(path=NON_ASCII_PATH, start_line=2, end_line=3, start_col=1, end_col=5)
    return Evidence.from_source(source, location, language=Language.PYTHON, context_lines=1)


def _chain(first: datetime, second: datetime) -> EgressRecord:
    head = f.make_egress_chain(1)[0]
    genesis = EgressRecord.seal(
        prev=None,
        timestamp=first,
        scan_id=head.scan_id,
        candidate_id=None,
        provider="mock",
        model="mock-1",
        task=None,
        level=PrivacyLevel.L4,
        payload_hash=head.payload_hash,
        token_counts=head.token_counts,
        outcome=head.outcome,
    )
    return EgressRecord.seal(
        prev=genesis,
        timestamp=second,
        scan_id=head.scan_id,
        candidate_id=head.candidate_id,
        provider="p" * 128,
        model="m" * 128,
        task=head.task,
        level=head.level,
        payload_hash=head.payload_hash,
        token_counts=head.token_counts,
        outcome=head.outcome,
    )


def edge_cases() -> list[tuple[str, KavachModel]]:
    location = f.make_location(path=NON_ASCII_PATH, symbol=None)
    minimal_finding = f.make_finding(
        evidence=(),
        cvss4_vector=None,
        cvss4_score=None,
        cwe=(),
        owasp=(),
        compliance=(),
        references=(),
        taint_path=None,
        correlation_key=None,
        first_seen_scan_id=None,
        created_at=ZERO_US,
    )
    return [
        ("location_non_ascii", location),
        ("location_columns", f.make_location(start_col=1, end_col=1)),
        ("region_plain", f.make_region()),
        ("taint_same_location_twice", TaintPath.from_locations(location, location)),
        (
            "candidate_minimal",
            f.make_candidate(taint_path=None, cwe=(), engine_severity=None, properties=()),
        ),
        ("candidate_max_message", f.make_candidate(message="m" * 2000)),
        ("slice_awkward_text", _awkward_slice()),
        (
            "payload_l4_no_newline",
            f.make_payload(
                text=SanitisedText("fn_1 ( )\r\nvar_2"),
                level=PrivacyLevel.L4,
                slice_id=None,
                line_map=(),
                pseudonym_count=0,
            ),
        ),
        (
            "verdict_minimal",
            f.make_verdict(cwe=(), cited_lines=(), needs_context=(), impact="", remediation=""),
        ),
        ("verdict_max_reasoning", f.make_verdict(reasoning="r" * 4000)),
        ("evidence_awkward_text", _awkward_evidence()),
        ("finding_minimal_zero_us", minimal_finding),
        (
            "finding_max_strings_max_us",
            f.make_finding(title="t" * 200, description="d" * 8000, created_at=MAX_US),
        ),
        ("egress_microseconds", _chain(ZERO_US, MAX_US)),
        ("project_minimal", f.make_project(name="n" * 200, repository_url=None, root=None)),
        (
            "scan_pending",
            f.make_scan(
                status=ScanStatus.PENDING,
                finished_at=None,
                summary=None,
                stages=(),
                started_at=MAX_US,
                languages=(),
                provider=None,
                model=None,
            ),
        ),
        ("scan_completed", f.make_scan()),
        ("summary_sample", f.make_summary()),
        (
            "summary_empty",
            ScanSummary.from_findings(
                [],
                files_scanned=0,
                lines_scanned=0,
                candidates_total=0,
                candidates_reviewed_by_llm=0,
                egress=EgressTotals.empty(),
                duration_seconds=0.0,
            ),
        ),
        ("totals_empty", EgressTotals.empty()),
    ]


@pytest.mark.parametrize(("name", "instance"), edge_cases(), ids=lambda value: str(value)[:40])
def test_edge_cases(name: str, instance: KavachModel) -> None:
    check_all(type(instance), instance)


def test_edge_cases_cover_every_strategy_model() -> None:
    covered = {type(instance) for _, instance in edge_cases()}
    assert covered >= {*EXPORTED_MODELS, EgressTotals}


# --- the checks are live: broken toy models must fail -------------------------------------


def _drop_zero_padding(value: datetime) -> str:
    # Bug under test: milliseconds without zero padding, so 5 ms is written as ".5" (500 ms).
    return f"{value:%Y-%m-%dT%H:%M:%S}.{value.microsecond // 1000}Z"


class ToyTimestamp(KavachModel):
    at: Annotated[AwareDatetime, PlainSerializer(_drop_zero_padding, when_used="json")]


class ToyList(KavachModel):
    items: list[int]


class ToyUnhashable(KavachModel):
    data: dict[str, int]


class ToyDocument(VersionedModel):
    name: str


def test_check_p3_catches_lossy_timestamps() -> None:
    instance = ToyTimestamp(at=datetime(2026, 1, 1, microsecond=5000, tzinfo=UTC))
    with pytest.raises(AssertionError, match="P3"):
        check_p3(ToyTimestamp, instance)


def test_check_p6_catches_list_fields() -> None:
    with pytest.raises(AssertionError, match=r"P6: mutable container: ToyList\.items is a list"):
        check_p6(ToyList, ToyList(items=[1, 2]))


def test_check_p7_catches_unhashable_fields() -> None:
    with pytest.raises(AssertionError, match="P7"):
        check_p7(ToyUnhashable, ToyUnhashable(data={"a": 1}))


def test_check_p8_catches_documents_missing_a_field() -> None:
    broken = ToyDocument.model_construct(schema_version=1)  # type: ignore[call-arg]  # the bug under test
    with pytest.raises(AssertionError, match="P8"):
        check_p8(ToyDocument, broken)


def test_checks_pass_on_a_sound_toy_model() -> None:
    check_all(ToyDocument, ToyDocument(name="ok"))


@given(st.sampled_from([name for name, _ in edge_cases()]))
def test_edge_case_names_are_unique(name: str) -> None:
    assert [n for n, _ in edge_cases()].count(name) == 1
