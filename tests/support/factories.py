"""Deterministic factories for the core models.

Every factory builds through the real constructors and class methods, so each returned object is
valid by construction and an invalid override raises ``ValidationError``. Ids and timestamps are
fixed constants unless overridden, so two calls give identical objects and golden files stay
stable. The defaults tell one coherent story: the SQL injection in ``src/bank/accounts.py`` at
line 88 (``AccountRepo.find_by_owner``), found by ``codekavach-rules`` with rule
``python.sqli.string-concat``.

Import as ``from tests.support.factories import make_finding``.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from codekavach.core.models import (
    Confidence,
    Language,
    PrivacyLevel,
    ScanStatus,
    Severity,
    SliceStrategy,
    StageStatus,
    sha256_hex,
)
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.egress import EgressRecord, TokenCounts
from codekavach.core.models.enums import DetectionOrigin, EgressOutcome, SegmentRole
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import (
    EngineRef,
    Finding,
    Impact,
    Likelihood,
    LLMReviewRef,
    Provenance,
)
from codekavach.core.models.fingerprint import FingerprintParts, compute_fingerprint, snippet_hash
from codekavach.core.models.ids import (
    CandidateId,
    FindingId,
    PayloadId,
    ProjectId,
    ScanId,
    SliceId,
    UlidFactory,
)
from codekavach.core.models.location import CodeRegion, Location
from codekavach.core.models.payload import LineMapEntry, SanitisedPayload
from codekavach.core.models.scan import Project, Scan, StageResult
from codekavach.core.models.slice import CodeSlice, SliceSegment
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.taint import TaintPath
from codekavach.core.models.taxonomy import Reference, TaxonomyRef
from codekavach.core.models.text import RawCode, SanitisedText, split_lines
from codekavach.core.models.verdict import LLMVerdict

FIXED_NOW = datetime(2026, 10, 5, 4, 30, tzinfo=UTC)
FIXED_NOW_MS = int(FIXED_NOW.timestamp() * 1000)

PROJECT_ID = ProjectId("proj_01ARYZ6S410000000000000000")
SCAN_ID = ScanId("scan_01ARYZ6S410000000000000000")
CANDIDATE_ID = CandidateId("cand_01ARYZ6S410000000000000001")
SLICE_ID = SliceId("slice_01ARYZ6S410000000000000002")
PAYLOAD_ID = PayloadId("pay_01ARYZ6S410000000000000003")
FINDING_ID = FindingId("find_01ARYZ6S410000000000000004")

SAMPLE_PATH = "src/bank/accounts.py"
SAMPLE_SYMBOL = "AccountRepo.find_by_owner"
SAMPLE_FIRST_LINE = 80
SAMPLE_LINE = 88
SAMPLE_RULE = "python.sqli.string-concat"
SAMPLE_ENGINE = "codekavach-rules"
CONFIG_HASH = "ab" * 32

# Twelve synthetic lines of AccountRepo, file lines 80 to 91. Illustrative only.
SAMPLE_SOURCE = (
    "class AccountRepo:\n"
    "    def __init__(self, conn):\n"
    "        self.conn = conn\n"
    "\n"
    "    # Look up every account owned by one customer.\n"
    "    # The owner comes straight from the request.\n"
    "    def find_by_owner(self, owner):\n"
    "        cur = self.conn.cursor()\n"
    '        cur.execute("SELECT * FROM accounts WHERE owner = \'" + owner + "\'")\n'
    "        return cur.fetchall()\n"
    "\n"
    "    def close(self): self.conn.close()\n"
)
# The whole synthetic file: blank lines 1 to 79, then SAMPLE_SOURCE.
SAMPLE_FILE = "\n" * (SAMPLE_FIRST_LINE - 1) + SAMPLE_SOURCE
# Hand-written pseudonymised counterpart of file lines 86 to 89 (the real pseudonymiser is E09).
SAMPLE_SANITISED = (
    "def fn_2(self, param_3):\n"
    "    var_4 = self.field_5.fn_6()\n"
    '    var_4.execute("SELECT * FROM tbl_7 WHERE col_8 = \'" + param_3 + "\'")\n'
    "    return var_4.fetchall()\n"
)
SLICE_START, SLICE_END = 86, 89
# The payload text whose hash the E02-18 ledger test vector records (E02-12 example).
VECTOR_PAYLOAD_TEXT = "def fn_1(param_2):\n    return param_2\n"


def fixed_ids() -> UlidFactory:
    """A ULID factory with a frozen clock at FIXED_NOW and counter-based entropy."""
    counter = iter(range(2**32))
    return UlidFactory(
        clock_ms=lambda: FIXED_NOW_MS,
        entropy=lambda size: next(counter).to_bytes(size, "big"),
    )


def _sample_lines(start: int, end: int) -> str:
    lines = split_lines(SAMPLE_FILE)[start - 1 : end]
    return "".join(line + "\n" for line in lines)


def make_location(**overrides: Any) -> Location:
    """The primary location of the sample SQL injection."""
    base = Location(
        path=SAMPLE_PATH, start_line=SAMPLE_LINE, end_line=SAMPLE_LINE, symbol=SAMPLE_SYMBOL
    )
    return base.evolve(**overrides) if overrides else base


def make_region(**overrides: Any) -> CodeRegion:
    """The line region of the sample slice."""
    base = CodeRegion(start_line=SLICE_START, end_line=SLICE_END)
    return base.evolve(**overrides) if overrides else base


def make_taint_path(**overrides: Any) -> TaintPath:
    """Owner parameter (source) flowing into cursor.execute (sink)."""
    source = Location(path=SAMPLE_PATH, start_line=86, end_line=86, symbol=SAMPLE_SYMBOL)
    base = TaintPath.from_locations(source, make_location())
    return base.evolve(**overrides) if overrides else base


def _sample_fingerprint() -> str:
    parts = FingerprintParts(
        engine=SAMPLE_ENGINE,
        rule_id=SAMPLE_RULE,
        path=SAMPLE_PATH,
        symbol=SAMPLE_SYMBOL,
        snippet_hash=snippet_hash([split_lines(SAMPLE_FILE)[SAMPLE_LINE - 1]]),
        start_line=SAMPLE_LINE,
    )
    return compute_fingerprint(parts)


def make_candidate(**overrides: Any) -> Candidate:
    """The candidate for the sample weakness, with the E02-10 vector A fingerprint."""
    base = Candidate.create(
        id=CANDIDATE_ID,
        rule_id=SAMPLE_RULE,
        engine=SAMPLE_ENGINE,
        cwe=(89,),
        locations=(make_location(),),
        taint_path=make_taint_path(),
        engine_severity=Severity.HIGH,
        fingerprint=_sample_fingerprint(),
        language=Language.PYTHON,
        message="SQL query built by string concatenation",
    )
    return base.evolve(**overrides) if overrides else base


def make_slice(**overrides: Any) -> CodeSlice:
    """The enclosing-function slice (file lines 86 to 89) of the sample candidate."""
    segment = SliceSegment(
        path=SAMPLE_PATH,
        region=make_region(),
        text=RawCode(_sample_lines(SLICE_START, SLICE_END)),
        role=SegmentRole.PRIMARY,
    )
    base = CodeSlice(
        id=SLICE_ID,
        candidate_id=CANDIDATE_ID,
        language=Language.PYTHON,
        strategy=SliceStrategy.ENCLOSING_FUNCTION,
        segments=(segment,),
        token_estimate=64,
    )
    return base.evolve(**overrides) if overrides else base


_PAYLOAD_BUILD_ARGS = frozenset(
    {"candidate_id", "slice_id", "text", "level", "pseudonym_count", "line_map"}
)


def make_payload(**overrides: Any) -> SanitisedPayload:
    """The L3 payload built from SAMPLE_SANITISED; hashed fields go through ``build``."""
    args: dict[str, Any] = {
        "candidate_id": CANDIDATE_ID,
        "slice_id": SLICE_ID,
        "text": SanitisedText(SAMPLE_SANITISED),
        "level": PrivacyLevel.L3,
        "pseudonym_count": 7,
        "line_map": (
            LineMapEntry(
                payload_start_line=1,
                payload_end_line=4,
                segment_index=0,
                file_start_line=SLICE_START,
            ),
        ),
    }
    args.update({key: value for key, value in overrides.items() if key in _PAYLOAD_BUILD_ARGS})
    rest = {key: value for key, value in overrides.items() if key not in _PAYLOAD_BUILD_ARGS}
    return SanitisedPayload.build(**args).evolve(id=PAYLOAD_ID, **rest)


def make_verdict(**overrides: Any) -> LLMVerdict:
    """A confident 'vulnerable' verdict in pseudonym space citing payload line 3."""
    base = LLMVerdict(
        is_vulnerable=True,
        confidence=Confidence.HIGH,
        cwe=(89,),
        reasoning="param_3 flows into var_4.execute through string concatenation.",
        impact="An attacker controlling param_3 can read every row of tbl_7.",
        remediation="Use a parameterised query with param_3 as a bound value.",
        cited_lines=(3,),
    )
    return base.evolve(**overrides) if overrides else base


def make_evidence(**overrides: Any) -> Evidence:
    """Snippet evidence around the sample line with two context lines."""
    base = Evidence.from_source(
        RawCode(SAMPLE_FILE), make_location(), language=Language.PYTHON, context_lines=2
    )
    return base.evolve(**overrides) if overrides else base


def make_finding(**overrides: Any) -> Finding:
    """The rated, restored finding for the sample weakness."""
    provenance = Provenance(
        origin=DetectionOrigin.DETERMINISTIC,
        scan_id=SCAN_ID,
        candidate_ids=(CANDIDATE_ID,),
        engines=(EngineRef(engine=SAMPLE_ENGINE, rule_id=SAMPLE_RULE),),
        llm_reviews=(
            LLMReviewRef(
                provider="mock",
                model="mock-1",
                task="triage",
                level=PrivacyLevel.L3,
                ledger_seq=1,
                is_vulnerable=True,
                confidence=Confidence.HIGH,
                reasoning="owner flows into cur.execute through string concatenation.",
            ),
        ),
        codekavach_version="0.1.0.dev0",
    )
    base = Finding(
        id=FINDING_ID,
        title="SQL injection in AccountRepo.find_by_owner",
        severity=Severity.HIGH,
        cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        cvss4_score=9.3,
        cwe=(89,),
        owasp=(TaxonomyRef(scheme="owasp-top10", id="A03", title="Injection", version="2021"),),
        compliance=(TaxonomyRef(scheme="pci-dss", id="6.2.4", version="4.0"),),
        locations=(make_location(),),
        evidence=(make_evidence(),),
        impact=Impact(level=4, narrative="An attacker can read every account row."),
        likelihood=Likelihood(level=4, rationale="The owner parameter comes from a request."),
        remediation="Use a parameterised query.",
        references=(
            Reference(title="CWE-89", url="https://cwe.mitre.org/data/definitions/89.html"),
        ),
        provenance=provenance,
        fingerprint=_sample_fingerprint(),
        confidence=Confidence.HIGH,
        description="The query string is built by concatenating the owner parameter.",
        taint_path=make_taint_path(),
        language=Language.PYTHON,
        created_at=FIXED_NOW,
    )
    return base.evolve(**overrides) if overrides else base


def make_egress_chain(n: int = 3) -> list[EgressRecord]:
    """``n`` sealed ledger entries; the first is the E02-18 test vector."""
    chain: list[EgressRecord] = []
    for index in range(n):
        previous = chain[-1] if chain else None
        chain.append(
            EgressRecord.seal(
                prev=previous,
                timestamp=FIXED_NOW + timedelta(seconds=index),
                scan_id=SCAN_ID,
                candidate_id=CANDIDATE_ID,
                provider="mock",
                model="mock-1",
                task="triage",
                level=PrivacyLevel.L3,
                payload_hash=sha256_hex(VECTOR_PAYLOAD_TEXT),
                token_counts=TokenCounts(prompt=120),
                outcome=EgressOutcome.SENT,
            )
        )
    return chain


def make_egress_totals(**overrides: Any) -> EgressTotals:
    """Totals over ``make_egress_chain()``."""
    base = EgressTotals.from_records(make_egress_chain())
    return base.evolve(**overrides) if overrides else base


def make_summary(**overrides: Any) -> ScanSummary:
    """The summary of a scan that produced ``make_finding()``."""
    base = ScanSummary.from_findings(
        [make_finding()],
        files_scanned=12,
        lines_scanned=900,
        candidates_total=1,
        candidates_reviewed_by_llm=1,
        egress=make_egress_totals(),
        duration_seconds=4.0,
    )
    return base.evolve(**overrides) if overrides else base


def make_project(**overrides: Any) -> Project:
    """The KavachBank sample project."""
    base = Project(
        id=PROJECT_ID,
        name="KavachBank",
        repository_url="https://example.test/kavachbank.git",
        created_at=FIXED_NOW,
    )
    return base.evolve(**overrides) if overrides else base


def make_scan(**overrides: Any) -> Scan:
    """A completed scan of the sample project with one succeeded stage."""
    base = Scan(
        id=SCAN_ID,
        project_id=PROJECT_ID,
        status=ScanStatus.COMPLETED,
        started_at=FIXED_NOW,
        finished_at=FIXED_NOW + timedelta(seconds=4),
        codekavach_version="0.1.0.dev0",
        config_hash=CONFIG_HASH,
        privacy_level=PrivacyLevel.L3,
        provider="mock",
        model="mock-1",
        languages=(Language.PYTHON,),
        stages=(
            StageResult(
                name="ingest",
                status=StageStatus.SUCCEEDED,
                started_at=FIXED_NOW,
                finished_at=FIXED_NOW + timedelta(seconds=1),
                items_out=12,
            ),
        ),
        summary=make_summary(),
    )
    return base.evolve(**overrides) if overrides else base
