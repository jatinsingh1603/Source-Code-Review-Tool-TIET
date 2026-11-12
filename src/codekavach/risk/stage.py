"""The rate stage: candidates and their restored verdicts become rated findings.

Owning epic: E13. MVP; extended by E29, which adds the CVSS v4.0 vector, the OWASP risk rating,
the risk matrix levels and the compliance mappings.

Deterministic findings are never discarded (``docs/research/INSIGHTS.md`` section 2.2 item 3). A
verdict that calls a candidate not vulnerable leaves the severity and the status alone, because the
lifecycle (E02-16) gives no model a path to ``false_positive``: only a human may set it. What the
verdict changes is the finding's confidence, which is what ranks it below the rest, and its
provenance records the answer and the reasoning. A scan in which the model dismisses everything
therefore still reports every deterministic finding. With no restored verdicts at all (the model
was disabled, blocked or failed) every candidate still becomes a finding.
"""

from pathlib import Path
from typing import Final

from codekavach import __version__
from codekavach.analysis.secrets.mask import mask_secret_values
from codekavach.config.models.root import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.candidate import Candidate
from codekavach.core.models.enums import (
    Confidence,
    DetectionOrigin,
    EgressOutcome,
    FindingStatus,
    PrivacyLevel,
    Severity,
)
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import (
    EngineRef,
    Finding,
    Impact,
    Likelihood,
    LLMReviewRef,
    Provenance,
)
from codekavach.core.models.ids import ScanId, new_finding_id
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.taxonomy import TaxonomyRef
from codekavach.core.models.text import RawCode
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.context import RunContext
from codekavach.core.pipeline.items import guard_item
from codekavach.core.pipeline.stage import StageCategory
from codekavach.core.store.base import ArtefactTypeError
from codekavach.ingest.models import SourceFile
from codekavach.privacy.egress.ledger import open_reader
from codekavach.privacy.restore.models import RestoredVerdict
from codekavach.risk.severity import map_severity

_log = get_logger(__name__)

RATE_FAILED: Final = "rate_failed"
TASK: Final = "triage"
PROMPT_VERSION: Final = "v1"
_IMPACT: Final = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_LIKELIHOOD: Final = {Confidence.LOW: 2, Confidence.MEDIUM: 3, Confidence.HIGH: 4}
_AUTH = "Identification and Authentication Failures"
_OWASP: Final[dict[int, tuple[str, str]]] = {
    **dict.fromkeys((77, 78, 79, 89, 94, 95), ("A03:2021", "Injection")),
    **dict.fromkeys((326, 327, 328, 330), ("A02:2021", "Cryptographic Failures")),
    **dict.fromkeys((259, 287, 306, 798), ("A07:2021", _AUTH)),
    **dict.fromkeys((22, 639, 862, 863), ("A01:2021", "Broken Access Control")),
    502: ("A08:2021", "Software and Data Integrity Failures"),
    918: ("A10:2021", "Server-Side Request Forgery"),
}

Reviewed = dict[str, tuple[str, str, int, PrivacyLevel]]


def _restored(ctx: RunContext) -> dict[str, RestoredVerdict]:
    if not ctx.artefacts.has(keys.VERDICTS_RESTORED):
        return {}
    try:
        items = ctx.artefacts.get_list(keys.VERDICTS_RESTORED, RestoredVerdict)
    except ArtefactTypeError:
        value = ctx.artefacts.get_object(keys.VERDICTS_RESTORED)
        items = (
            [item for item in value if isinstance(item, RestoredVerdict)]
            if isinstance(value, list)
            else []
        )
    return {str(item.candidate_id): item for item in items}


def _ledger_entries(ctx: RunContext) -> Reviewed:
    """Per candidate: provider, model, ledger sequence and level of its request, when ledgered."""
    if ctx.state_dir is None:
        return {}
    wanted = {EgressOutcome.SENT, EgressOutcome.NOT_SENT_DRY_RUN}
    try:
        reader = open_reader(ctx.state_dir, settings=ctx.config)
        return {
            str(record.candidate_id): (record.provider, record.model, record.seq, record.level)
            for record in reader.records(ctx.scan_id)
            if record.outcome in wanted and record.candidate_id is not None
        }
    except Exception:  # noqa: BLE001 - provenance is best effort; the finding does not need it
        _log.warning("rate_ledger_unreadable")
        return {}


def _totals(ctx: RunContext) -> EgressTotals:
    if ctx.state_dir is None:
        return EgressTotals.empty()
    try:
        return open_reader(ctx.state_dir, settings=ctx.config).totals(ctx.scan_id)
    except Exception:  # noqa: BLE001 - no readable ledger means nothing is claimed to have left
        return EgressTotals.empty()


def _evidence(
    candidate: Candidate,
    root: Path,
    cache: dict[str, RawCode | None],
    settings: Settings | None = None,
) -> tuple[Evidence, ...]:
    """Snippets cut from the original files, so they carry real names and real line numbers."""
    items: list[Evidence] = []
    for location in candidate.locations:
        if location.path not in cache:
            try:
                text = (root / location.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                cache[location.path] = None
            else:
                if settings is not None:
                    # Credential values never reach a report: mask every detected secret.
                    text = mask_secret_values(text, location.path, candidate.language, settings)
                cache[location.path] = RawCode(text)
        source = cache[location.path]
        if source is None:
            continue
        try:
            item = Evidence.from_source(source, location, language=candidate.language)
            items.append(item.model_copy(update={"masked": True}) if settings else item)
        except ValueError:
            continue
    return tuple(items)


def build_finding(
    ctx: RunContext,
    candidate: Candidate,
    verdict: RestoredVerdict | None,
    *,
    cache: dict[str, RawCode | None],
    ledger: Reviewed,
) -> Finding:
    """One finding from ``candidate`` and, when it has a usable answer, its restored verdict."""
    usable = verdict if verdict is not None and not verdict.verdict_dropped else None
    severity = map_severity(candidate, None)
    confidence = candidate.engine_confidence or Confidence.MEDIUM
    cwe = candidate.cwe or (usable.cwe if usable else ())
    if usable is not None and usable.is_vulnerable is False:
        confidence = Confidence.LOW  # ranks below the rest; severity and status are untouched
    reviews: tuple[LLMReviewRef, ...] = ()
    entry = ledger.get(str(candidate.id))
    if usable is not None and entry is not None:
        provider, model, seq, level = entry
        reviews = (
            LLMReviewRef(
                provider=provider,
                model=model,
                task=TASK,
                prompt_version=PROMPT_VERSION,
                level=level,
                ledger_seq=seq,
                is_vulnerable=usable.is_vulnerable,
                confidence=usable.confidence,
                reasoning=usable.reasoning[:4000],
            ),
        )
    owasp = tuple(
        TaxonomyRef(
            scheme="owasp-top10", id=_OWASP[number][0], title=_OWASP[number][1], version="2021"
        )
        for number in cwe[:1]
        if number in _OWASP
    )
    first_line = (candidate.message.splitlines() or [""])[0].strip()
    title = (first_line or candidate.rule_id)[:200]
    return Finding(
        id=new_finding_id(),
        title=title,
        severity=severity,
        cwe=cwe,
        owasp=owasp,
        locations=candidate.locations,
        evidence=_evidence(candidate, ctx.source_root, cache, ctx.config),
        impact=Impact(level=_IMPACT[severity], narrative=(usable.impact if usable else "")[:4000]),
        likelihood=Likelihood(level=_LIKELIHOOD[confidence]),
        remediation=(usable.remediation if usable else "")[:8000],
        status=FindingStatus.OPEN,
        provenance=Provenance(
            origin=DetectionOrigin.DETERMINISTIC,
            scan_id=ScanId(ctx.scan_id),
            candidate_ids=(candidate.id,),
            engines=(
                EngineRef(
                    engine=candidate.engine,
                    rule_id=candidate.rule_id,
                    engine_version=candidate.engine_version,
                ),
            ),
            llm_reviews=reviews,
            codekavach_version=__version__,
        ),
        fingerprint=candidate.fingerprint,
        confidence=confidence,
        description=candidate.message,
        taint_path=candidate.taint_path,
        kind=candidate.kind,
        language=candidate.language,
        created_at=utc_now(),
        first_seen_scan_id=ScanId(ctx.scan_id),
    )


class RateStage:
    """Turns candidates and their restored verdicts into rated findings and a scan summary."""

    name = "rate"
    version = "1"
    requires = frozenset({keys.CANDIDATES})
    optional_requires = frozenset({keys.VERDICTS_RESTORED, keys.FILES})
    provides = frozenset({keys.FINDINGS, keys.SCAN_SUMMARY})
    category = StageCategory.RATE

    def run(self, ctx: RunContext) -> None:
        """Publish a finding per candidate that could be built, and a summary of them."""
        candidates = ctx.artefacts.get_list(keys.CANDIDATES, Candidate)
        verdicts = _restored(ctx)
        ledger = _ledger_entries(ctx)
        cache: dict[str, RawCode | None] = {}
        findings: list[Finding] = []
        for candidate in candidates:
            ctx.check_cancelled()
            with guard_item(ctx, str(candidate.id), RATE_FAILED):
                findings.append(
                    build_finding(
                        ctx, candidate, verdicts.get(str(candidate.id)), cache=cache, ledger=ledger
                    )
                )
        findings.sort(key=Finding.sort_key)
        files = (
            ctx.artefacts.get_list(keys.FILES, SourceFile) if ctx.artefacts.has(keys.FILES) else []
        )
        summary = ScanSummary.from_findings(
            findings,
            files_scanned=len(files),
            lines_scanned=sum(file.line_count for file in files),
            candidates_total=len(candidates),
            candidates_reviewed_by_llm=sum(1 for v in verdicts.values() if not v.verdict_dropped),
            egress=_totals(ctx),
            duration_seconds=0.0,
        )
        _log.info("findings_rated", findings=len(findings), candidates=len(candidates))
        ctx.artefacts.put(keys.FINDINGS, findings)
        ctx.artefacts.put(keys.SCAN_SUMMARY, summary)
