"""Build the report document from a stored scan, its findings and the ledger.

Owning epic: E13. MVP; extended by E30, which adds the full audit report structure.

``build_report_document`` is the seam ``codekavach report``, the demo and the server call. It is
deterministic and model-free: given the same scan, findings, settings and ledger summary it
produces the same document (apart from ``generated_at``). ``summarise_ledger`` gathers the figures
of the privacy attestation from the ledger and the scan's stored artefacts; it reads counts,
hashes and settings, and counts placeholder tokens in the sanitised payloads when the ledger key is
available, never keeping any payload text.
"""

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codekavach import __version__
from codekavach.config import Settings
from codekavach.config.models.llm import ProviderSettings
from codekavach.core.log import get_logger
from codekavach.core.models.disclosure import DisclosureRows
from codekavach.core.models.finding import Finding
from codekavach.core.models.payload import PLACEHOLDER_PATTERN
from codekavach.core.models.scan import Scan
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline import keys
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.egress.ledger import open_reader
from codekavach.report.model.control import (
    Classification,
    DistributionEntry,
    DocumentControl,
    SignOff,
    VersionEntry,
)
from codekavach.report.model.document import (
    OFFLINE_NOTICE,
    PrivacyAttestation,
    ReportDocument,
    ZeroLeak,
)
from codekavach.report.model.finding_view import FindingView
from codekavach.report.model.ids import ReportIdScheme, assign_report_ids
from codekavach.report.model.method import (
    Methodology,
    ToolRecord,
    default_privacy_levels,
    default_rating_method,
    default_steps,
)
from codekavach.report.model.scope import (
    Coverage,
    EngagementScope,
    Limitation,
    Target,
    not_reviewed_label,
)
from codekavach.report.narrative import AggregatedFacts, build_roadmap, executive_summary

_log = get_logger(__name__)
DEFAULT_TITLE = "Secure Source Code Review"
DEFAULT_ORGANISATION = "CodeKavach Security Review"
_PLACEHOLDER = re.compile(PLACEHOLDER_PATTERN)
_KIND_NAMES = {"SECRET": "secret", "PII": "pii", "TERM": "term"}


@dataclass(frozen=True)
class LedgerSummary:
    """The ledger and artefact figures of one scan that the attestation prints."""

    head_hash: str | None = None
    entries: int = 0
    by_outcome: tuple[tuple[str, int], ...] = ()
    disclosure: tuple[tuple[str, str], ...] = ()
    not_reviewed: tuple[tuple[str, int], ...] = ()
    zero_leak: ZeroLeak = field(default_factory=ZeroLeak)
    chain_ok: bool | None = None
    chain_detail: str | None = None
    requests_sent: int = 0
    requests_blocked: int = 0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    placeholders_by_type: tuple[tuple[str, int], ...] = ()
    placeholders_counted: bool = False
    files: tuple[tuple[str, str, int], ...] = ()
    provider: str | None = None
    model: str | None = None


def _placeholder_counts(reader: Any, records: Sequence[Any]) -> tuple[tuple[str, int], ...] | None:
    """Placeholder tokens by type across the scan's payloads, or None when unreadable."""
    counts: Counter[str] = Counter()
    seen: set[str] = set()
    try:
        for record in records:
            if record.payload_hash in seen:
                continue
            seen.add(record.payload_hash)
            text = reader.payload_text(record.payload_hash)
            if text is None:
                continue
            for match in _PLACEHOLDER.finditer(text.expose()):
                kind = _KIND_NAMES.get(match.group(1), match.group(1).lower())
                counts[f"{kind}:{match.group(2)}"] += 1
    except Exception:  # noqa: BLE001 - payloads need the ledger key; counts are optional
        _log.info("report_payload_counts_unavailable")
        return None
    return tuple(sorted(counts.items(), key=lambda pair: (-pair[1], pair[0])))


def _files(store: OnDiskArtefactStore) -> tuple[tuple[str, str, int], ...]:
    if not store.has(keys.FILES):
        return ()
    raw = store.get_json(keys.FILES)
    if not isinstance(raw, list):
        return ()
    rows: list[tuple[str, str, int]] = []
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            lines = item.get("line_count")
            rows.append(
                (
                    str(item["path"]),
                    str(item.get("language", "unknown")),
                    int(lines) if isinstance(lines, int) else 0,
                )
            )
    return tuple(sorted(rows))


def summarise_ledger(
    state_dir: Path, scan_id: str, settings: Settings, *, zero_leak: ZeroLeak | None = None
) -> LedgerSummary:
    """The ledger head, counts, chain verification, disclosure figures and failure counts."""
    head: str | None = None
    entries = 0
    outcomes: Counter[str] = Counter()
    chain_ok: bool | None = None
    chain_detail: str | None = None
    sent = blocked = prompt = completion = 0
    placeholders: tuple[tuple[str, int], ...] | None = None
    endpoints: Counter[tuple[str, str]] = Counter()
    try:
        reader = open_reader(state_dir, settings=settings)
        records = list(reader.records(scan_id))
        for record in records:
            head, entries = record.entry_hash, entries + 1
            endpoints[(str(record.provider), str(record.model))] += 1
            outcomes[record.outcome.value] += 1
            if record.block_code is not None:
                blocked += 1
            elif record.ref_seq is None:
                sent += 1
                # A response record repeats its request's prompt count; count each request once.
                prompt += record.token_counts.prompt
            completion += record.token_counts.completion or 0
        try:
            report = reader.verify_chain()
            chain_ok = bool(report.ok)
            if not report.ok:
                chain_detail = f"{report.reason} at entry {report.first_bad_seq}"
        except Exception:  # noqa: BLE001 - an unverifiable chain is reported as such
            chain_ok, chain_detail = False, "the chain could not be read"
        placeholders = _placeholder_counts(reader, records)
    except Exception:  # noqa: BLE001 - a scan that sent nothing has no ledger to read
        _log.info("report_ledger_unreadable")
    disclosure: tuple[tuple[str, str], ...] = ()
    failures: Counter[str] = Counter()
    files: tuple[tuple[str, str, int], ...] = ()
    try:
        store = OnDiskArtefactStore.open_existing(StateLayout(state_dir), scan_id)
        if store.has(keys.DISCLOSURE):
            disclosure = store.get(keys.DISCLOSURE, DisclosureRows).rows
        if store.has(keys.ITEM_FAILURES):
            raw = store.get_json(keys.ITEM_FAILURES)
            if isinstance(raw, list):
                failures.update(
                    str(item.get("error_code", "unknown")) for item in raw if isinstance(item, dict)
                )
        files = _files(store)
    except Exception:  # noqa: BLE001 - the report is still useful without these figures
        _log.info("report_artefacts_unreadable")
    return LedgerSummary(
        head_hash=head,
        entries=entries,
        by_outcome=tuple(sorted(outcomes.items())),
        disclosure=disclosure,
        not_reviewed=tuple(sorted(failures.items())),
        zero_leak=zero_leak or ZeroLeak(),
        chain_ok=chain_ok,
        chain_detail=chain_detail,
        requests_sent=sent,
        requests_blocked=blocked,
        tokens_prompt=prompt,
        tokens_completion=completion,
        placeholders_by_type=placeholders or (),
        placeholders_counted=placeholders is not None,
        files=files,
        provider=endpoints.most_common(1)[0][0][0] if endpoints else None,
        model=endpoints.most_common(1)[0][0][1] if endpoints else None,
    )


def _preset_is_remote(provider_id: str) -> bool:
    """Whether the built-in preset ``provider_id`` sends to a remote host (unknown: remote)."""
    try:
        return bool(ProviderSettings.model_validate({"preset": provider_id}).is_remote)
    except Exception:  # noqa: BLE001 - an unknown id is treated as remote, the safe reading
        return True


def _attestation(
    scan: Scan, settings: Settings | None, ledger: LedgerSummary | None
) -> PrivacyAttestation:
    summary = ledger or LedgerSummary()
    default_level = str(scan.privacy_level.value)
    levels: tuple[tuple[str, str], ...] = ()
    retention = "not set"
    local = True
    notice: str | None = None
    if settings is not None:
        privacy = settings.privacy
        default_level = str(privacy.level)
        levels = tuple(
            (rule.pattern, "never_send" if rule.never_send else str(rule.level))
            for rule in privacy.paths
        )
        days = privacy.vault.retention_days
        retention = f"{days} days" if days is not None else "kept until the vault is destroyed"
        if scan.provider is not None and scan.provider in settings.llm.providers:
            provider = settings.llm.providers[scan.provider]
            local = not provider.is_remote
            if provider.kind.value in {"mock", "replay"}:
                notice = OFFLINE_NOTICE.format(kind=provider.kind.value)
        elif scan.provider in {"mock", "replay"}:
            notice = OFFLINE_NOTICE.format(kind=scan.provider)
        elif scan.provider is not None and _preset_is_remote(scan.provider):
            # A built-in preset (for example agentrouter) that the settings do not list.
            local = False
    elif scan.provider in {"mock", "replay"}:
        notice = OFFLINE_NOTICE.format(kind=scan.provider)
    if scan.provider is not None and scan.provider not in {"mock", "replay"} and settings is None:
        local = False
    return PrivacyAttestation(
        default_level=default_level,
        levels=levels,
        provider=scan.provider,
        model=scan.model,
        provider_is_local=local,
        offline_notice=notice,
        disclosure=summary.disclosure,
        ledger_head_hash=summary.head_hash,
        ledger_entries=summary.entries,
        entries_by_outcome=summary.by_outcome,
        zero_leak=summary.zero_leak,
        retention=retention,
        chain_ok=summary.chain_ok,
        chain_detail=summary.chain_detail,
        requests_sent=summary.requests_sent,
        requests_blocked=summary.requests_blocked,
        tokens_prompt=summary.tokens_prompt,
        tokens_completion=summary.tokens_completion,
        placeholders_by_type=summary.placeholders_by_type,
        placeholders_counted=summary.placeholders_counted,
    )


def _limitations(
    scan: Scan, summary: ScanSummary, ledger: LedgerSummary | None
) -> tuple[Limitation, ...]:
    items = [
        Limitation(
            id="L-1",
            kind="technique",
            statement="Static analysis only: the application was not executed, so runtime "
            "configuration, deployed infrastructure and third-party services were not tested.",
        ),
        Limitation(
            id="L-2",
            kind="coverage",
            statement="Rule and taint coverage is limited to the languages and frameworks the "
            "rule packs model; business-logic flaws that do not match a rule may be missed.",
        ),
        Limitation(
            id="L-3",
            kind="model",
            statement="Model-assisted assessments are probabilistic and advisory. They lower or "
            "raise confidence but never remove a deterministic finding from this report.",
        ),
        Limitation(
            id="L-4",
            kind="dependencies",
            statement="Known-vulnerable third-party components are reported only where an "
            "engine for dependency analysis was enabled for the run.",
        ),
    ]
    if scan.provider in {None, "mock", "replay"}:
        items.append(
            Limitation(
                id="L-5",
                kind="model",
                statement="No live language model was used in this run; model verdicts, where "
                "shown, come from the offline provider.",
            )
        )
    if ledger and ledger.not_reviewed:
        failed = "; ".join(
            f"{not_reviewed_label(code)} ({count})" for code, count in ledger.not_reviewed
        )
        items.append(
            Limitation(
                id=f"L-{len(items) + 1}",
                kind="coverage",
                statement=f"Some candidates were not reviewed by the model: {failed}. They are "
                "still reported with their deterministic rating.",
            )
        )
    _ = summary
    return tuple(items)


def _tools(scan: Scan, findings: Sequence[Finding]) -> tuple[ToolRecord, ...]:
    tools: dict[str, ToolRecord] = {
        "CodeKavach": ToolRecord(
            name="CodeKavach",
            version=scan.codekavach_version or __version__,
            role="Orchestration, rules, taint analysis, privacy layer, reporting",
            licence="MIT",
            configuration_digest=scan.config_hash[:16],
        )
    }
    for finding in findings:
        for engine in finding.provenance.engines:
            name = engine.engine
            if name not in tools:
                tools[name] = ToolRecord(
                    name=name,
                    version=engine.engine_version or "n/a",
                    role="Detection engine",
                )
    if scan.provider:
        tools[f"model:{scan.provider}"] = ToolRecord(
            name=f"{scan.provider} / {scan.model or 'default model'}",
            version="n/a",
            role="Model-assisted triage (advisory)",
            distribution_mode="local" if scan.provider in {"mock", "replay"} else "remote API",
        )
    return tuple(tools.values())


def build_report_document(
    scan: Scan,
    findings: Sequence[Finding],
    settings: Settings | None = None,
    ledger_summary: LedgerSummary | None = None,
    *,
    organisation: str | None = None,
    prepared_for: str | None = None,
    project_name: str | None = None,
    previous_ids: dict[str, str] | None = None,
    id_scheme: ReportIdScheme | None = None,
) -> ReportDocument:
    """The document for ``scan``: control, narrative, findings, attestation and appendices.

    The summary is the scan's own when it stored one, otherwise it is aggregated from ``findings``.
    """
    ordered = tuple(sorted(findings, key=Finding.sort_key))
    if scan.provider is None and ledger_summary is not None and ledger_summary.provider:
        # Older scan records do not carry the provider; the ledger names who each request went to.
        scan = scan.model_copy(
            update={
                "provider": ledger_summary.provider,
                "model": scan.model or ledger_summary.model,
            }
        )
    reporting = settings.reporting if settings is not None else None
    summary = scan.summary or ScanSummary.from_findings(
        ordered,
        files_scanned=0,
        lines_scanned=0,
        candidates_total=len(ordered),
        candidates_reviewed_by_llm=0,
        egress=EgressTotals.empty(),
        duration_seconds=0.0,
    )
    wanted = reporting is None or reporting.include_privacy_attestation
    now = utc_now()
    year = scan.started_at.year
    project = project_name or (
        settings.project.name if settings is not None and settings.project.name else "the project"
    )
    org = organisation or (reporting.auditor if reporting and reporting.auditor else None)
    org = org or DEFAULT_ORGANISATION
    client = prepared_for or (
        settings.project.client if settings is not None and settings.project.client else project
    )
    classification = reporting.classification if reporting else "Confidential"
    context = reporting.snippet_context_lines if reporting else None
    min_rank = reporting.min_severity.rank if reporting else 0
    ids = assign_report_ids(ordered, scheme=id_scheme, year=year, previous=previous_ids)
    views = tuple(
        FindingView.from_finding(
            finding,
            report_id=ids.get(str(finding.id)) or ids[finding.fingerprint],
            context_lines=context,
        )
        for finding in ordered
        if finding.severity.rank >= min_rank
    )
    files = ledger_summary.files if ledger_summary else ()
    languages = [lang.display_name for lang, _ in summary.by_language] or [
        lang.display_name for lang in scan.languages
    ]
    if not languages and files:
        languages = sorted({lang for _, lang, _ in files})
    languages = [lang for lang in languages if lang and lang.lower() not in {"unknown", "other"}]
    files_analysed = summary.files_scanned or len(files)
    lines_analysed = summary.lines_scanned or sum(lines for _, _, lines in files)
    facts = AggregatedFacts.from_views(
        views,
        languages=languages,
        files_analysed=files_analysed,
        lines_analysed=lines_analysed,
        privacy_level=str(scan.privacy_level.value),
    )
    roadmap = build_roadmap(views)
    start = scan.started_at.strftime("%d %B %Y")
    end = (scan.finished_at or scan.started_at).strftime("%d %B %Y")
    period = f"on {start}" if start == end else f"between {start} and {end}"
    executive = executive_summary(
        facts,
        views,
        roadmap,
        client=client,
        project=project,
        period=period,
        provider=scan.provider if scan.provider not in {"mock", "replay"} else None,
        model=scan.model,
    )
    report_id = f"CK-RPT-{year}-{str(scan.id)[-8:].upper()}"
    issue_date = now.strftime("%d %B %Y")
    control = DocumentControl(
        report_id=report_id,
        version="1.0",
        issue_date=issue_date,
        prepared_by=org,
        prepared_for=client,
        classification=Classification(label=classification, banner=classification.upper()),
        versions=(
            VersionEntry(
                version="1.0",
                date=issue_date,
                author=org,
                change="Report issued from scan " + str(scan.id),
            ),
        ),
        distribution=(
            DistributionEntry(name="Security lead", role="Recipient", organisation=client),
            DistributionEntry(name="Engineering lead", role="Recipient", organisation=client),
        ),
        sign_offs=(
            SignOff(name="Lead reviewer", role="Prepared by"),
            SignOff(name="Quality reviewer", role="Reviewed by"),
            SignOff(name="Engagement owner", role="Approved by"),
        ),
        copyright_notice=f"(c) {year} {org}. Prepared for {client}.",
    )
    scope = EngagementScope(
        client_name=client,
        engagement_id=f"ENG-{str(scan.id)[-8:].upper()}",
        period_start=start,
        period_end=end,
        targets=(
            Target(
                repository=project,
                commit=scan.git_commit,
                branch=scan.git_branch,
                languages=tuple(languages),
                paths_excluded=tuple(settings.scan.exclude) if settings is not None else (),
            ),
        ),
        objectives=(
            "Identify security weaknesses in the source code that could compromise the "
            "confidentiality, integrity or availability of the application and its data.",
            "Rate each weakness by severity, likelihood and impact, and map it to CWE, OWASP "
            "and the applicable compliance controls.",
            "Provide actionable remediation guidance prioritised by risk.",
            "Demonstrate, through the egress ledger, exactly what code left the client "
            "environment during model-assisted review.",
        ),
        assumptions=(
            "The code reviewed is the version identified by the commit above.",
            "Configuration and secrets supplied at deployment time are outside the scope.",
        ),
    )
    coverage = Coverage(
        files_discovered=len(files) or files_analysed,
        files_analysed=files_analysed,
        lines_analysed=lines_analysed,
        by_language=tuple(
            (lang.display_name if lang.value != "unknown" else "other files", count)
            for lang, count in summary.by_language
        ),
        candidates_total=summary.candidates_total,
        candidates_reviewed_by_llm=summary.candidates_reviewed_by_llm,
        not_reviewed=ledger_summary.not_reviewed if ledger_summary else (),
        files_reviewed=tuple(path for path, _, _ in files),
    )
    methodology = Methodology(
        steps=default_steps(),
        tools=_tools(scan, ordered),
        rule_packs=tuple(sorted({e.engine for f in ordered for e in f.provenance.engines})),
        privacy_levels=default_privacy_levels(),
        techniques_not_performed=(
            "Dynamic application security testing (DAST)",
            "Manual penetration testing",
            "Infrastructure and cloud configuration review",
        ),
    )
    return ReportDocument(
        title=(reporting.title if reporting and reporting.title else DEFAULT_TITLE),
        classification=classification,
        auditor=reporting.auditor if reporting else None,
        generated_at=now,
        scan=scan,
        summary=summary,
        findings=ordered,
        not_reviewed=ledger_summary.not_reviewed if ledger_summary else (),
        privacy_attestation=_attestation(scan, settings, ledger_summary) if wanted else None,
        tools=tuple((tool.name, tool.version) for tool in methodology.tools),
        report_id=report_id,
        version="1.0",
        project_name=project,
        organisation=org,
        prepared_for=client,
        control=control,
        scope=scope,
        coverage=coverage,
        methodology=methodology,
        rating_method=default_rating_method(),
        views=views,
        facts=facts,
        executive=executive,
        roadmap=roadmap,
        limitations=_limitations(scan, summary, ledger_summary),
    )
