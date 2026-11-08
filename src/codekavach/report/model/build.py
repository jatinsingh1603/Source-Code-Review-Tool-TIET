"""Build the report document from a stored scan, its findings and the ledger.

Owning epic: E13. MVP; extended by E30, which adds the full audit report structure.

``build_report_document`` is the seam ``codekavach report`` calls (E05-15). ``summarise_ledger``
gathers the figures of the privacy attestation from the ledger and the scan's stored artefacts; it
reads counts, hashes and settings and never a payload text, a mapping or a key.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from codekavach import __version__
from codekavach.config import Settings
from codekavach.core.log import get_logger
from codekavach.core.models.disclosure import DisclosureRows
from codekavach.core.models.finding import Finding
from codekavach.core.models.scan import Scan
from codekavach.core.models.summary import EgressTotals, ScanSummary
from codekavach.core.models.timeutil import utc_now
from codekavach.core.pipeline import keys
from codekavach.core.store.artefacts import OnDiskArtefactStore
from codekavach.core.store.layout import StateLayout
from codekavach.privacy.egress.ledger import open_reader
from codekavach.report.model.document import (
    OFFLINE_NOTICE,
    PrivacyAttestation,
    ReportDocument,
    ZeroLeak,
)

_log = get_logger(__name__)
DEFAULT_TITLE = "Secure Source Code Review"


@dataclass(frozen=True)
class LedgerSummary:
    """The ledger and artefact figures of one scan that the attestation prints."""

    head_hash: str | None = None
    entries: int = 0
    by_outcome: tuple[tuple[str, int], ...] = ()
    disclosure: tuple[tuple[str, str], ...] = ()
    not_reviewed: tuple[tuple[str, int], ...] = ()
    zero_leak: ZeroLeak = field(default_factory=ZeroLeak)


def summarise_ledger(
    state_dir: Path, scan_id: str, settings: Settings, *, zero_leak: ZeroLeak | None = None
) -> LedgerSummary:
    """The ledger head, the entry counts, the disclosure figures and the failure counts."""
    head: str | None = None
    entries = 0
    outcomes: Counter[str] = Counter()
    try:
        for record in open_reader(state_dir, settings=settings).records(scan_id):
            head, entries = record.entry_hash, entries + 1
            outcomes[record.outcome.value] += 1
    except Exception:  # noqa: BLE001 - a scan that sent nothing has no ledger to read
        _log.info("report_ledger_unreadable")
    disclosure: tuple[tuple[str, str], ...] = ()
    failures: Counter[str] = Counter()
    try:
        store = OnDiskArtefactStore.open_existing(StateLayout(state_dir), scan_id)
        if store.has(keys.DISCLOSURE):
            disclosure = store.get(keys.DISCLOSURE, DisclosureRows).rows
        if store.has(keys.ITEM_FAILURES):
            raw = store.get_object(keys.ITEM_FAILURES)
            if isinstance(raw, list):
                failures.update(
                    str(item.get("error_code", "unknown")) for item in raw if isinstance(item, dict)
                )
    except Exception:  # noqa: BLE001 - the report is still useful without these figures
        _log.info("report_artefacts_unreadable")
    return LedgerSummary(
        head_hash=head,
        entries=entries,
        by_outcome=tuple(sorted(outcomes.items())),
        disclosure=disclosure,
        not_reviewed=tuple(sorted(failures.items())),
        zero_leak=zero_leak or ZeroLeak(),
    )


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
    elif scan.provider in {"mock", "replay"}:
        notice = OFFLINE_NOTICE.format(kind=scan.provider)
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
    )


def build_report_document(
    scan: Scan,
    findings: Sequence[Finding],
    settings: Settings | None = None,
    ledger_summary: LedgerSummary | None = None,
) -> ReportDocument:
    """The document for ``scan``: its findings, summary and privacy attestation.

    The summary is the scan's own when it stored one, otherwise it is aggregated from ``findings``.
    """
    ordered = tuple(sorted(findings, key=Finding.sort_key))
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
    return ReportDocument(
        title=(reporting.title if reporting and reporting.title else DEFAULT_TITLE),
        classification=reporting.classification if reporting else "Confidential",
        auditor=reporting.auditor if reporting else None,
        generated_at=utc_now(),
        scan=scan,
        summary=summary,
        findings=ordered,
        not_reviewed=ledger_summary.not_reviewed if ledger_summary else (),
        privacy_attestation=_attestation(scan, settings, ledger_summary) if wanted else None,
        tools=(("CodeKavach", __version__),),
    )
