"""Read the results of a finished scan from its state directory for the API.

Owning epic: E32.

Findings, payloads, slices and ledger entries live where the pipeline wrote them, below the
scan's workspace. This module turns them into the JSON the dashboard reads: finding rows and
details, the privacy summary, ledger entries and the original-versus-sent pair of one entry. The
ledger reader decrypts payload text only on the paths that return it (``ledger_entry_detail``),
which the routers guard with ``privacy:read_original``. Nothing here reads the vault: the
original side of a pair is the slice the pipeline stored, not a reversal of pseudonyms (I3).
"""

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from codekavach.core.log import get_logger

if TYPE_CHECKING:
    from codekavach.config import Settings
    from codekavach.core.models.finding import Finding

_log = get_logger("codekavach.server.results")

SEVERITY_ORDER: Final = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK: Final = {name: 5 - index for index, name in enumerate(SEVERITY_ORDER)}
_REDACTION: Final = re.compile(r"<(SECRET|PII|TERM):[a-z][a-z0-9_]{0,47}:[1-9][0-9]{0,5}>")
_RENAME: Final = re.compile(r"\b(fn|cls|var|param|field|mod|const|file)_[0-9]+\b")
_LITERAL: Final = re.compile(r"<(STR|NUM|LIT|URL|PATH)[A-Z_]*(:[a-z0-9_]+)*(:[0-9]+)?>")
_KIND_OF: Final = {"SECRET": "secret", "PII": "pii", "TERM": "literal"}


@dataclass
class ScanPaths:
    """Where one server scan keeps its files."""

    workspace: Path

    @property
    def source(self) -> Path:
        """The copy of the code that was scanned."""
        return self.workspace / "src"

    @property
    def state_dir(self) -> Path:
        """The pipeline's state directory."""
        return self.source / ".codekavach"

    @property
    def reports(self) -> Path:
        """Rendered reports."""
        return self.workspace / "reports"

    @property
    def scan_json(self) -> Path:
        """The core ``Scan`` record as JSON."""
        return self.workspace / "scan.json"

    @property
    def settings_json(self) -> Path:
        """The configuration overrides the scan ran with."""
        return self.workspace / "settings.json"


@dataclass
class PrivacySummary:
    """The figures of ``GET /scans/{id}/privacy``."""

    level: str
    provider: str | None
    model: str | None
    payloads: int = 0
    blocked: int = 0
    sent: int = 0
    recorded: int = 0
    placeholders_by_type: dict[str, int] = field(default_factory=dict)
    pseudonyms: int = 0
    tokens_sent: int = 0
    chain_ok: bool = False
    chain_entries: int = 0
    ledger_head: str | None = None
    zero_leak: dict[str, Any] = field(default_factory=dict)
    privacy_score: int | None = None
    attestation_text: str = ""

    def to_json(self) -> dict[str, Any]:
        """The JSON form."""
        return dict(self.__dict__)


def scan_env(home: Path, passphrase_env: str) -> dict[str, str]:
    """The environment the configuration loader sees for a server scan.

    Nested ``CODEKAVACH_<SECTION>__<KEY>`` variables of the server process pass through (so an
    operator configures providers and the vault the usual way); ``CODEKAVACH_HOME`` points into
    the data directory, and the vault uses the server's passphrase file unless the operator chose
    a key source.
    """
    env = {key: value for key, value in os.environ.items() if key.startswith("CODEKAVACH_")}
    env = {key: value for key, value in env.items() if "__" in key or key == "CODEKAVACH_CONFIG"}
    env["CODEKAVACH_HOME"] = str(home)
    if "CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE" not in env:
        env["CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE"] = "passphrase"
        env["CODEKAVACH_PRIVACY__VAULT__PASSPHRASE"] = f"env:{passphrase_env}"
    return env


def load_scan_settings(paths: ScanPaths, home: Path, passphrase_env: str) -> "Settings":
    """The settings a stored scan ran with (overrides re-applied)."""
    from codekavach.config import load_settings  # noqa: PLC0415

    overrides: dict[str, Any] = {}
    if paths.settings_json.is_file():
        overrides = json.loads(paths.settings_json.read_text(encoding="utf-8"))
    loaded = load_settings(
        target=paths.source, env=scan_env(home, passphrase_env), cli_overrides=overrides or None
    )
    return loaded.settings


def read_findings(paths: ScanPaths, core_scan_id: str) -> "list[Finding]":
    """The findings the pipeline stored for the scan."""
    from codekavach.core.models.finding import Finding  # noqa: PLC0415
    from codekavach.core.pipeline import keys  # noqa: PLC0415
    from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415

    store = OnDiskArtefactStore.open_existing(StateLayout(paths.state_dir), core_scan_id)
    return list(store.get_list(keys.FINDINGS, Finding)) if store.has(keys.FINDINGS) else []


def finding_columns(finding: "Finding") -> dict[str, Any]:
    """The indexed columns of a finding row."""
    location = finding.locations[0] if finding.locations else None
    engines = finding.provenance.engines
    severity = str(finding.severity.value)
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": severity,
        "severity_rank": SEVERITY_RANK.get(severity, 0),
        "confidence": str(finding.confidence.value),
        "cwe": ",".join(f"CWE-{int(item)}" for item in finding.cwe),
        "path": str(location.path) if location else "",
        "line": int(location.start_line) if location else 0,
        "rule_id": engines[0].rule_id if engines else "",
        "engine": engines[0].engine if engines else "",
        "fingerprint": finding.fingerprint,
        "status": str(finding.status.value),
        "data": finding.model_dump(mode="json"),
    }


def _taxonomy(data: dict[str, Any], scheme_prefix: str) -> list[str]:
    return [
        str(item.get("id"))
        for key in ("taxonomy", "owasp", "compliance")
        for item in data.get(key) or []
        if isinstance(item, dict) and str(item.get("scheme", "")).startswith(scheme_prefix)
    ]


def _verdict(data: dict[str, Any]) -> dict[str, Any] | None:
    reviews = (data.get("provenance") or {}).get("llm_reviews") or []
    if not reviews:
        return None
    review = reviews[-1]
    impact = data.get("impact") or {}
    return {
        "is_vulnerable": review.get("is_vulnerable"),
        "confidence": review.get("confidence"),
        "reasoning": review.get("reasoning", ""),
        "impact": review.get("impact") or impact.get("narrative", ""),
        "remediation": review.get("remediation") or data.get("remediation", ""),
        "model": review.get("model"),
        "provider": review.get("provider"),
        "level": review.get("level"),
        "ledger_seq": review.get("ledger_seq"),
        "task": review.get("task"),
    }


def _score(data: dict[str, Any], name: str) -> Any:
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    return data.get(name, risk.get(name) if risk else None)


def finding_summary(row: Any) -> dict[str, Any]:
    """The list-view JSON of a finding row (``FindingRow``)."""
    data: dict[str, Any] = row.data or {}
    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "cwe": [item for item in row.cwe.split(",") if item],
        "owasp": [item.get("id") for item in data.get("owasp") or [] if isinstance(item, dict)],
        "path": row.path,
        "line": row.line,
        "rule_id": row.rule_id,
        "engine": row.engine,
        "status": row.status,
        "assignee": row.assignee,
        "fingerprint": row.fingerprint,
        "cvss4_score": _score(data, "cvss4_score"),
        "cvss31_score": _score(data, "cvss31_score"),
        "llm_reviewed": bool((data.get("provenance") or {}).get("llm_reviews")),
        "updated_at": row.updated_at,
    }


def _snippet(data: dict[str, Any]) -> dict[str, Any] | None:
    for evidence in data.get("evidence") or []:
        if not isinstance(evidence, dict):
            continue
        lines = evidence.get("lines") or []
        if not lines:
            continue
        location = evidence.get("location") or {}
        return {
            "path": location.get("path"),
            "language": evidence.get("language"),
            "start_line": lines[0].get("number"),
            "lines": [
                {"number": line.get("number"), "text": line.get("text", "")} for line in lines
            ],
            "highlight": [item.get("line") for item in evidence.get("highlights") or []],
            "masked": bool(evidence.get("masked")),
        }
    return None


def _taint_steps(data: dict[str, Any]) -> list[dict[str, Any]]:
    path = data.get("taint_path") or {}
    steps = []
    for index, step in enumerate(path.get("steps") or [], start=1):
        if not isinstance(step, dict):
            continue
        location = step.get("location") or {}
        steps.append(
            {
                "index": index,
                "kind": step.get("kind") or step.get("role"),
                "label": step.get("label") or step.get("description") or step.get("symbol"),
                "path": location.get("path"),
                "line": location.get("start_line"),
                "code": step.get("code") or step.get("text"),
            }
        )
    return steps


def finding_detail(row: Any) -> dict[str, Any]:
    """The detail JSON of a finding row: everything the dashboard's finding page shows."""
    data: dict[str, Any] = dict(row.data or {})
    detail = finding_summary(row)
    impact = data.get("impact") or {}
    likelihood = data.get("likelihood") or {}
    references = [
        item if isinstance(item, dict) else {"url": str(item)}
        for item in data.get("references") or []
    ]
    compliance = [
        {
            "framework": item.get("scheme"),
            "clause": item.get("id"),
            "title": item.get("title"),
        }
        for item in (data.get("compliance") or []) + (data.get("taxonomy") or [])
        if isinstance(item, dict)
    ]
    detail.update(
        {
            "description": data.get("description", ""),
            "kind": data.get("kind"),
            "language": data.get("language"),
            "owasp": data.get("owasp") or [],
            "asvs": data.get("asvs") or _taxonomy(data, "asvs"),
            "capec": data.get("capec") or _taxonomy(data, "capec"),
            "cvss4_vector": _score(data, "cvss4_vector"),
            "cvss31_vector": _score(data, "cvss31_vector"),
            "likelihood": likelihood,
            "impact": impact,
            "compliance": compliance,
            "locations": data.get("locations") or [],
            "evidence": {
                "snippet": _snippet(data),
                "taint_path": _taint_steps(data),
            },
            "llm_verdict": _verdict(data),
            "remediation": data.get("remediation", ""),
            "references": references,
            "provenance": data.get("provenance") or {},
            "risk": data.get("risk"),
            "raw": data,
        }
    )
    return detail


def markup(text: str, side: str) -> list[dict[str, Any]]:
    """Spans of ``text`` that the privacy layer replaced: secrets, PII, identifiers, literals."""
    found = [
        (_KIND_OF.get(match.group(1), "literal"), match) for match in _REDACTION.finditer(text)
    ]
    found += [("identifier", match) for match in _RENAME.finditer(text)]
    found += [("literal", match) for match in _LITERAL.finditer(text)]
    spans: list[dict[str, Any]] = [
        {"kind": kind, "start": match.start(), "end": match.end(), "side": side}
        for kind, match in found
    ]
    spans.sort(key=lambda item: (item["start"], item["end"]))
    kept: list[dict[str, Any]] = []
    cursor = -1
    for span in spans:
        if span["start"] >= cursor:
            kept.append(span)
            cursor = span["end"]
    return kept


class ScanResults:
    """Reader of one stored scan's ledger, payloads and slices."""

    def __init__(self, paths: ScanPaths, core_scan_id: str, settings: "Settings") -> None:
        from codekavach.core.store.layout import StateLayout  # noqa: PLC0415
        from codekavach.privacy.egress.ledger import open_reader  # noqa: PLC0415

        self.paths = paths
        self.scan_id = core_scan_id
        self.settings = settings
        self.layout = StateLayout(paths.state_dir)
        self.reader = open_reader(self.layout, settings=settings)

    def records(self) -> list[Any]:
        """The ledger records of the scan, in order."""
        try:
            return list(self.reader.records(self.scan_id))
        except Exception as error:  # noqa: BLE001 - a scan that sent nothing has no ledger
            _log.info("server_ledger_unreadable", error_type=type(error).__name__)
            return []

    def entries(self) -> list[Any]:
        """The payload entries (payload, candidate, slice, outcome) of the scan."""
        from codekavach.cli.privacy import collect  # noqa: PLC0415
        from codekavach.privacy.inspect_source import open_payload_source  # noqa: PLC0415

        try:
            source = open_payload_source(self.layout, self.scan_id, settings=self.settings)
            return collect(source, self.scan_id, [], None)
        except Exception as error:  # noqa: BLE001 - no payloads were prepared
            _log.info("server_payloads_unreadable", error_type=type(error).__name__)
            return []

    def chain(self) -> tuple[bool, int, str | None]:
        """``(ok, entries, reason)`` of the ledger chain walk."""
        try:
            report = self.reader.verify_chain()
        except Exception as error:  # noqa: BLE001 - an unreadable ledger is not intact
            return False, 0, type(error).__name__
        return bool(report.ok), int(report.entries), report.reason

    def verify(self, terms_file: Path | None) -> list[Any]:
        """The ledger verification steps (chain, payloads, listed terms)."""
        from codekavach.cli.ledger import VERIFY_STEPS, VerifyContext, run_verify  # noqa: PLC0415

        context = VerifyContext(
            reader=self.reader,
            options={
                "terms_files": [terms_file] if terms_file and terms_file.is_file() else [],
                "ignore_case": True,
                "include_blocked": True,
            },
        )
        return run_verify(context, VERIFY_STEPS)

    def privacy_summary(
        self, *, level: str, provider: str | None, model: str | None, terms_file: Path | None
    ) -> PrivacySummary:
        """Every figure of the privacy page, computed from the ledger and the payloads."""
        summary = PrivacySummary(level=level, provider=provider, model=model)
        records = self.records()
        outcomes = Counter(str(record.outcome.value) for record in records)
        summary.blocked = outcomes.get("blocked", 0)
        summary.sent = outcomes.get("sent", 0)
        summary.recorded = outcomes.get("not_sent_dry_run", 0)
        summary.tokens_sent = sum(
            int(record.token_counts.prompt)
            for record in records
            if str(record.outcome.value) == "sent"
        )
        if records:
            summary.ledger_head = records[-1].entry_hash
            if summary.model is None:
                summary.model = records[-1].model
        entries = self.entries()
        summary.payloads = len(entries)
        placeholders: Counter[str] = Counter()
        for entry in entries:
            for ref in entry.payload.placeholders:
                placeholders[str(ref.kind.value)] += 1
            summary.pseudonyms += int(entry.payload.pseudonym_count)
        if summary.pseudonyms:
            placeholders["identifier"] += summary.pseudonyms
        summary.placeholders_by_type = dict(sorted(placeholders.items()))
        summary.chain_ok, summary.chain_entries, _reason = self.chain()
        results = self.verify(terms_file)
        terms = next((result for result in results if result.name == "terms"), None)
        hits = terms.data.get("hits", []) if terms is not None else []
        checked = int(terms.data.get("checked", 0)) if terms is not None else 0
        summary.zero_leak = {
            "checked": checked,
            "occurrences": len(hits),
            "passed": bool(terms is not None and checked > 0 and not hits),
        }
        summary.attestation_text = attestation(summary)
        return summary

    def ledger_rows(self, finding_of: dict[str, str]) -> list[dict[str, Any]]:
        """The ledger entries as JSON, with the finding each candidate became."""
        rows = []
        for record in self.records():
            candidate = str(record.candidate_id) if record.candidate_id else None
            rows.append(
                {
                    "seq": record.seq,
                    "timestamp": record.timestamp,
                    "provider": record.provider,
                    "model": record.model,
                    "task": record.task,
                    "level": str(record.level.value),
                    "payload_hash": record.payload_hash,
                    "entry_hash": record.entry_hash,
                    "prev_hash": record.prev_hash,
                    "tokens": int(record.token_counts.prompt)
                    + int(record.token_counts.completion or 0),
                    "tokens_prompt": int(record.token_counts.prompt),
                    "tokens_completion": record.token_counts.completion,
                    "outcome": str(record.outcome.value),
                    "block_code": record.block_code,
                    "ref_seq": record.ref_seq,
                    "candidate_id": candidate,
                    "finding_id": finding_of.get(candidate or ""),
                }
            )
        return rows

    def ledger_entry_detail(self, seq: int, finding_of: dict[str, str]) -> dict[str, Any] | None:
        """One entry with its payload text, the original slice and the change markup."""
        rows = {row["seq"]: row for row in self.ledger_rows(finding_of)}
        row = rows.get(seq)
        if row is None:
            return None
        text = self.reader.payload_text(row["payload_hash"])
        payload_text = text.expose() if text is not None else ""
        original_text = ""
        original_start = None
        candidate = row["candidate_id"]
        if candidate:
            for entry in self.entries():
                if str(entry.payload.candidate_id) == candidate and entry.slice is not None:
                    segments = entry.slice.segments
                    original_text = "\n...\n".join(segment.text.expose() for segment in segments)
                    original_start = segments[0].region.start_line if segments else None
                    break
        return {
            "entry": row,
            "payload_text": payload_text,
            "original_text": original_text,
            "original_start_line": original_start,
            "markup": markup(payload_text, "sent"),
        }


def attestation(summary: PrivacySummary) -> str:
    """A factual paragraph about what this scan disclosed, built from the measured figures."""
    provider = summary.provider or "none"
    model = summary.model or "provider default"
    chain = (
        f"The egress ledger hash chain verified intact over {summary.chain_entries} entries"
        + (f" (head {summary.ledger_head[:16]})" if summary.ledger_head else "")
        if summary.chain_ok
        else "The egress ledger hash chain did not verify"
    )
    zero = summary.zero_leak
    if zero.get("checked"):
        leak = (
            f"The zero-leak check searched every payload for {zero['checked']} listed project "
            f"terms and found {zero['occurrences']} occurrence(s)."
        )
    else:
        leak = "No list of project terms was available, so the zero-leak check did not run."
    placeholders = ", ".join(
        f"{count} {kind}" for kind, count in summary.placeholders_by_type.items()
    )
    return (
        f"At privacy level {summary.level}, {summary.payloads} sanitised payload(s) were prepared "
        f"for provider {provider} (model {model}); {summary.sent} were sent, "
        f"{summary.recorded} were recorded without sending and {summary.blocked} were blocked by "
        f"the egress guard. Replacements made before egress: {placeholders or 'none'}. "
        f"{chain}. {leak} Only sanitised payloads are eligible to leave the machine; original "
        "code, secrets and the pseudonym vault stay local."
    )
