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
from codekavach.server.db.engine import as_utc

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
# Server variables that are not configuration and must not reach a scan's loader.
SERVER_ONLY_VARIABLES: Final = (
    "CODEKAVACH_ADMIN_PASSWORD",
    "CODEKAVACH_SERVER_",
    "CODEKAVACH_DEV",
)


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

    @property
    def reviews_json(self) -> Path:
        """Pipeline scan ids of the on-demand reviews run over this scan (``POST .../review``)."""
        return self.workspace / "reviews.json"

    def review_scan_ids(self) -> list[str]:
        """The pipeline scan ids of this scan's on-demand reviews, oldest first."""
        try:
            data = json.loads(self.reviews_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [str(item) for item in data if isinstance(item, str)]

    def add_review_scan_id(self, core_scan_id: str) -> None:
        """Remember an on-demand review's pipeline scan id, so its ledger entries are listed."""
        ids = self.review_scan_ids()
        if core_scan_id not in ids:
            ids.append(core_scan_id)
            self.reviews_json.write_text(json.dumps(ids), encoding="utf-8")


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
    bytes_sent: int = 0
    lines_sent: int = 0
    bytes_recorded: int = 0
    lines_recorded: int = 0
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

    The ``CODEKAVACH_*`` variables of the server process pass through, except the server's own,
    so an operator configures providers, key variables such as ``CODEKAVACH_AGENTROUTER_API_KEY``
    and the vault the usual way; ``CODEKAVACH_HOME`` points into the data directory, and the vault
    uses the server's passphrase file unless the operator chose a key source.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("CODEKAVACH_") and not key.startswith(SERVER_ONLY_VARIABLES)
    }
    env["CODEKAVACH_HOME"] = str(home)
    reference = env.get("CODEKAVACH_PRIVACY__VAULT__PASSPHRASE", "")
    unset = reference.startswith("env:") and not os.environ.get(reference[4:])
    if "CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE" not in env or (
        env["CODEKAVACH_PRIVACY__VAULT__KEY_SOURCE"] == "passphrase" and unset
    ):
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


def policy_withheld(paths: ScanPaths, core_scan_id: str) -> int:
    """How many candidates the privacy policy withheld from the model (0 when unrecorded)."""
    from codekavach.core.pipeline import keys  # noqa: PLC0415
    from codekavach.core.store.artefacts import OnDiskArtefactStore  # noqa: PLC0415
    from codekavach.core.store.layout import StateLayout  # noqa: PLC0415
    from codekavach.privacy.policy.records import PolicyDecisionRow  # noqa: PLC0415

    try:
        store = OnDiskArtefactStore.open_existing(StateLayout(paths.state_dir), core_scan_id)
        if not store.has(keys.POLICY_DECISIONS):
            return 0
        rows = store.get_list(keys.POLICY_DECISIONS, PolicyDecisionRow)
    except Exception:  # noqa: BLE001 - a log line, never a reason to fail the scan
        return 0
    return sum(1 for row in rows if row.withheld)


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


LEVEL_WORDS: Final = {1: "Very low", 2: "Low", 3: "Medium", 4: "High", 5: "Very high"}


def _kb_entry(cwes: list[int]) -> Any:
    """The knowledge-base entry of the first known CWE (``None`` without the catalogue)."""
    try:
        from codekavach.risk.taxonomy.loader import load_knowledge_base  # noqa: PLC0415

        base = load_knowledge_base()
    except Exception:  # noqa: BLE001 - the catalogue is optional enrichment
        return None
    if base is None:
        return None
    for cwe in cwes:
        entry = base.entry(cwe)
        if entry is not None:
            return entry
    return None


def _cwe_numbers(data: dict[str, Any]) -> list[int]:
    numbers = []
    for item in data.get("cwe") or []:
        try:
            numbers.append(int(str(item).upper().removeprefix("CWE-")))
        except ValueError:
            continue
    return numbers


def _refs(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [item for item in data.get(key) or [] if isinstance(item, dict)]


def _taxonomy(data: dict[str, Any], scheme_prefix: str) -> list[str]:
    return [
        str(item.get("id"))
        for key in ("taxonomy", "owasp", "compliance")
        for item in _refs(data, key)
        if str(item.get("scheme", "")).startswith(scheme_prefix)
    ]


def _owasp_text(data: dict[str, Any]) -> str | None:
    refs = _refs(data, "owasp")
    if not refs:
        return None
    first = refs[0]
    return f"{first.get('id')} {first.get('title') or ''}".strip()


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


def _level_word(value: Any) -> str | None:
    level = value.get("level") if isinstance(value, dict) else value
    return LEVEL_WORDS.get(level) if isinstance(level, int) else None


def finding_summary(row: Any) -> dict[str, Any]:
    """The list-view JSON of a finding row (``FindingRow``)."""
    data: dict[str, Any] = row.data or {}
    cwes = [item for item in row.cwe.split(",") if item]
    location = (data.get("locations") or [{}])[0]
    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "cwe": cwes[0] if cwes else None,
        "cwes": cwes,
        "owasp": _owasp_text(data),
        "path": row.path,
        "line": row.line,
        "locations": [location] if location else [],
        "rule_id": row.rule_id,
        "engine": row.engine,
        "status": row.status,
        "assignee": row.assignee,
        "fingerprint": row.fingerprint,
        "cvss4_score": _score(data, "cvss4_score"),
        "cvss31_score": _score(data, "cvss31_score"),
        "likelihood": _level_word(data.get("likelihood")),
        "impact": _level_word(data.get("impact")),
        "llm_reviewed": bool((data.get("provenance") or {}).get("llm_reviews")),
        "created_at": data.get("created_at"),
        "updated_at": as_utc(row.updated_at),
    }


def _code(data: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    for evidence in _refs(data, "evidence"):
        lines = evidence.get("lines") or []
        if not lines:
            continue
        location = evidence.get("location") or {}
        highlights = [
            {"start": item.get("line"), "end": item.get("line")}
            for item in evidence.get("highlights") or []
            if isinstance(item, dict)
        ]
        if not highlights and location.get("start_line"):
            highlights = [{"start": location["start_line"],
                           "end": location.get("end_line") or location["start_line"]}]  # fmt: skip
        code = {
            "path": location.get("path"),
            "language": evidence.get("language"),
            "start_line": lines[0].get("number"),
            "lines": [
                {"number": line.get("number"), "text": line.get("text", "")} for line in lines
            ],
            "highlight": highlights,
            "masked": bool(evidence.get("masked")),
        }
        text = "\n".join(str(line.get("text", "")) for line in lines)
        return code, text
    return None, None


def _line_text(source_root: Path | None, path: str | None, number: int | None) -> str | None:
    if source_root is None or not path or not number:
        return None
    try:
        target = (source_root / path).resolve()
        if source_root.resolve() not in target.parents:
            return None
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return lines[number - 1].strip() if 0 < number <= len(lines) else None


def _taint_steps(data: dict[str, Any], source_root: Path | None) -> list[dict[str, Any]]:
    path = data.get("taint_path") or {}
    steps = []
    for index, step in enumerate(path.get("steps") or [], start=1):
        if not isinstance(step, dict):
            continue
        location = step.get("location") or {}
        role = str(step.get("role") or "propagation")
        steps.append(
            {
                "index": index,
                "kind": {"sanitizer": "sanitiser"}.get(role, role),
                "label": step.get("note") or location.get("symbol") or role,
                "path": location.get("path"),
                "line": location.get("start_line"),
                "code": _line_text(source_root, location.get("path"), location.get("start_line")),
            }
        )
    return steps


def _impact(data: dict[str, Any], cwes: list[int]) -> dict[str, Any]:
    """The impact of a finding, with the weakness's impact statement in place of a rating line.

    Without a model verdict the rate stage writes a rating summary ("CVSS v4.0 9.3 (CVSS-B); ...")
    as the narrative; the scores are shown beside it already, so the page says what the weakness
    lets an attacker do instead, as the report does.
    """
    from codekavach.report.model.library import lookup  # noqa: PLC0415

    impact = dict(data.get("impact") or {})
    if str(impact.get("narrative") or "").startswith("CVSS v4.0"):
        impact["narrative"] = lookup(tuple(cwes)).impact
    return impact


def finding_detail(row: Any, source_root: Path | None = None) -> dict[str, Any]:
    """The detail JSON of a finding row: everything the dashboard's finding page shows."""
    data: dict[str, Any] = dict(row.data or {})
    detail = finding_summary(row)
    cwes = _cwe_numbers(data)
    entry = _kb_entry(cwes)
    asvs = _taxonomy(data, "asvs") or list(getattr(entry, "asvs", ()) or ())
    capec = _taxonomy(data, "capec") or [
        f"CAPEC-{item}" for item in getattr(entry, "capec", ()) or ()
    ]
    references = [
        {"title": item.get("title") or item.get("url"), "url": item.get("url")}
        for item in _refs(data, "references")
    ]
    if entry is not None and not references:
        references = [{"title": f"CWE-{entry.id}: {entry.name}", "url": entry.url}]
    compliance = [
        {"framework": item.get("scheme"), "clause": item.get("id"), "title": item.get("title")}
        for item in _refs(data, "compliance") + _refs(data, "taxonomy")
    ]
    code, snippet = _code(data)
    verdict = _verdict(data)
    detail.update(
        {
            "description": data.get("description", ""),
            "kind": data.get("kind"),
            "language": data.get("language"),
            "cwe_name": getattr(entry, "name", None),
            "owasp_refs": _refs(data, "owasp"),
            "asvs": ", ".join(asvs) or None,
            "asvs_refs": asvs,
            "capec": ", ".join(capec) or None,
            "capec_refs": capec,
            "cvss4_vector": _score(data, "cvss4_vector"),
            "cvss31_vector": _score(data, "cvss31_vector"),
            "likelihood_detail": data.get("likelihood") or {},
            "impact_detail": _impact(data, cwes),
            "compliance": compliance,
            "locations": data.get("locations") or [],
            "evidence": {
                "snippet": snippet,
                "code": code,
                "taint_path": _taint_steps(data, source_root),
            },
            "llm": verdict,
            "llm_verdict": verdict,
            "remediation": data.get("remediation") or getattr(entry, "remediation", None) or "",
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
        self._sizes: dict[str, tuple[int, int] | None] = {}

    def payload_size(self, payload_hash: str) -> tuple[int, int] | None:
        """``(bytes, lines)`` of a stored payload; ``None`` when it is not stored or pruned.

        Only the size is kept: the text is decrypted, measured and dropped, never returned.
        """
        if payload_hash not in self._sizes:
            try:
                text = self.reader.payload_text(payload_hash)
            except Exception as error:  # noqa: BLE001 - an unreadable body has no size
                _log.info("server_payload_unreadable", error_type=type(error).__name__)
                text = None
            if text is None:
                self._sizes[payload_hash] = None
            else:
                body = text.expose()
                self._sizes[payload_hash] = (len(body.encode("utf-8")), _line_count(body))
        return self._sizes[payload_hash]

    @property
    def scan_ids(self) -> list[str]:
        """The scan's pipeline id, then those of its on-demand reviews (same state directory)."""
        return [self.scan_id, *(i for i in self.paths.review_scan_ids() if i != self.scan_id)]

    def records(self) -> list[Any]:
        """The ledger records of the scan and of its on-demand reviews, in order."""
        out: list[Any] = []
        for scan_id in self.scan_ids:
            try:
                out.extend(self.reader.records(scan_id))
            except Exception as error:  # noqa: BLE001 - a scan that sent nothing has no ledger
                _log.info("server_ledger_unreadable", error_type=type(error).__name__)
        return sorted(out, key=lambda record: record.seq)

    def review_egress(self) -> dict[str, int]:
        """What the on-demand reviews of this scan's findings sent after the scan finished.

        The scan's privacy summary and attestation are fixed when it completes; a later "Review
        with model" adds its payloads to the scan's ledger only. These figures let the Privacy
        Centre say so instead of showing fewer payloads than the ledger.
        """
        out = {"payloads": 0, "bytes_sent": 0, "tokens_sent": 0, "blocked": 0}
        for scan_id in self.scan_ids[1:]:
            try:
                records = self.reader.records(scan_id)
            except Exception as error:  # noqa: BLE001 - a review that sent nothing has no ledger
                _log.info("server_ledger_unreadable", error_type=type(error).__name__)
                continue
            for record in records:
                outcome = str(record.outcome.value)
                if outcome == "blocked":
                    out["blocked"] += 1
                if outcome != "sent":
                    continue
                out["payloads"] += 1
                out["tokens_sent"] += int(record.token_counts.prompt)
                out["bytes_sent"] += (self.payload_size(record.payload_hash) or (0, 0))[0]
        return out

    def entries(self) -> list[Any]:
        """The payload entries (payload, candidate, slice, outcome) of the scan and its reviews."""
        from codekavach.cli.privacy import collect  # noqa: PLC0415
        from codekavach.privacy.inspect_source import open_payload_source  # noqa: PLC0415

        out: list[Any] = []
        for scan_id in self.scan_ids:
            try:
                source = open_payload_source(self.layout, scan_id, settings=self.settings)
                out.extend(collect(source, scan_id, [], None))
            except Exception as error:  # noqa: BLE001 - no payloads were prepared
                _log.info("server_payloads_unreadable", error_type=type(error).__name__)
        return out

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
        for record in records:
            outcome = str(record.outcome.value)
            if outcome not in {"sent", "not_sent_dry_run"}:
                continue
            size = self.payload_size(record.payload_hash) or (0, 0)
            if outcome == "sent":
                summary.bytes_sent += size[0]
                summary.lines_sent += size[1]
            else:
                summary.bytes_recorded += size[0]
                summary.lines_recorded += size[1]
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
            size = self.payload_size(record.payload_hash)
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
                    "bytes": size[0] if size else None,
                    "lines_sent": size[1] if size else None,
                    "policy_rule_key": record.policy_rule_key,
                    "block_code": record.block_code,
                    "ref_seq": record.ref_seq,
                    "candidate_id": candidate,
                    "finding_id": finding_of.get(candidate or ""),
                }
            )
        return rows

    def fingerprint_of(self, seq: int) -> str | None:
        """The fingerprint of the candidate behind ledger entry ``seq`` (stable across scans)."""
        record = next((item for item in self.records() if item.seq == seq), None)
        if record is None or not record.candidate_id:
            return None
        for entry in self.entries():
            if str(entry.payload.candidate_id) == str(record.candidate_id):
                return str(entry.candidate.fingerprint) if entry.candidate is not None else None
        return None

    def seq_of_fingerprint(self, fingerprint: str) -> int | None:
        """The first sent or dry-run ledger entry of the candidate with ``fingerprint``."""
        candidates = {
            str(entry.payload.candidate_id)
            for entry in self.entries()
            if entry.candidate is not None and str(entry.candidate.fingerprint) == fingerprint
        }
        for record in self.records():
            outcome = str(record.outcome.value)
            if outcome in {"sent", "not_sent_dry_run"} and str(record.candidate_id) in candidates:
                return int(record.seq)
        return None

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
        path: str | None = None
        slice_lines: list[int] = []
        source_line = sink_line = None
        other_segments = 0
        candidate = row["candidate_id"]
        if candidate:
            for entry in self.entries():
                if str(entry.payload.candidate_id) == candidate and entry.slice is not None:
                    segments = entry.slice.segments
                    primary = next(
                        (s for s in segments if str(getattr(s.role, "value", s.role)) == "primary"),
                        segments[0],
                    )
                    path = str(primary.path)
                    # The original pane shows one file: the primary segment's. Line numbers are
                    # the file's own, so only that file's segments count towards the slice.
                    own = [segment for segment in segments if str(segment.path) == path]
                    other_segments = len(segments) - len(own)
                    for segment in own:
                        lines = range(segment.region.start_line, segment.region.end_line + 1)
                        slice_lines.extend(lines)
                        role = str(getattr(segment.role, "value", segment.role))
                        if role == "taint_step" and source_line is None:
                            source_line = segment.region.start_line
                        if role == "primary" and sink_line is None:
                            sink_line = segment.region.start_line
                    span = self._file_span(path, min(slice_lines), max(slice_lines))
                    if span is not None:
                        original_start, original_text = span
                    else:
                        original_text = "\n...\n".join(segment.text.expose() for segment in own)
                        original_start = own[0].region.start_line
                    # The candidate's own location is the sink; a primary segment that covers a
                    # whole function or file starts above it.
                    located = entry.candidate.locations if entry.candidate is not None else ()
                    if located and str(located[0].path) == path:
                        line = int(located[0].start_line)
                        if line in slice_lines:
                            sink_line = line
                    break
        marks = markup(payload_text, "payload")
        kinds = Counter(str(item["kind"]) for item in marks)
        return {
            "entry": row,
            "payload_text": payload_text,
            "original_text": original_text,
            "original_start_line": original_start,
            "path": path,
            "start_line": original_start,
            "slice_lines": sorted(set(slice_lines)),
            "source_line": source_line,
            "sink_line": sink_line,
            "other_file_segments": other_segments,
            "bytes": row.get("bytes"),
            "lines_sent": _line_count(payload_text),
            "lines_original": _line_count(original_text),
            "lines_total": self._file_lines(path),
            "replacements": dict(sorted(kinds.items())),
            "markup": marks,
        }

    def _file_span(self, path: str, first: int, last: int) -> tuple[int, str] | None:
        """Lines ``first - 2`` to ``last + 2`` of the scanned copy of ``path``, with the start line.

        Contiguous, so the original pane can number every line truthfully and tint the slice; the
        lines between slice segments are shown untinted (they were not sent).
        """
        root = self.paths.source.resolve()
        try:
            target = (root / path).resolve()
            if root not in target.parents:
                return None
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        if not lines or first < 1 or last > len(lines):
            return None
        start = max(1, first - 2)
        end = min(len(lines), last + 2)
        return start, "\n".join(lines[start - 1 : end])

    def _file_lines(self, path: str | None) -> int | None:
        """Line count of a scanned file (the count only; the file is not returned)."""
        if not path:
            return None
        root = self.paths.source.resolve()
        try:
            target = (root / path).resolve()
            if root not in target.parents:
                return None
            return _line_count(target.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            return None


def _line_count(text: str) -> int:
    return len(text.splitlines()) if text else 0


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
    from codekavach.privacy.attest import count_words  # noqa: PLC0415

    zero = summary.zero_leak
    if zero.get("checked"):
        leak = (
            f"The zero-leak check searched every payload for {zero['checked']} listed project "
            f"terms and found {count_words(int(zero['occurrences']), 'occurrence')}."
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


def with_attestation(
    summary: PrivacySummary,
    paths: ScanPaths,
    core_scan_id: str,
    settings: "Settings",
    terms_file: Path | None,
) -> dict[str, Any]:
    """The privacy JSON: the server's figures overlaid with the E28 attestation and score.

    ``build_attestation`` (``codekavach.privacy.attestation``) adds the privacy score and its
    components, the policy and disclosure figures. The listed terms of the project are given to it
    for the zero-leak search only (the scan itself ran without them). Without that module the
    server's own figures are returned unchanged.
    """
    data = summary.to_json()
    try:
        from codekavach.core.models.enums import PrivacyLevel  # noqa: PLC0415
        from codekavach.privacy.attestation import build_attestation  # noqa: PLC0415

        checked = settings
        if terms_file is not None:
            privacy = settings.privacy.model_copy(update={"domain_terms_file": terms_file})
            checked = settings.model_copy(update={"privacy": privacy})
        attestation = build_attestation(
            paths.state_dir, core_scan_id, checked, level=PrivacyLevel(summary.level)
        )
        extra = attestation.to_api()
    except Exception as error:  # noqa: BLE001 - the attestation is an optional enrichment
        _log.info("server_attestation_unavailable", error_type=type(error).__name__)
        return data
    mine_checked = bool(data.get("zero_leak", {}).get("checked"))
    for key, value in extra.items():
        if value is None or (key == "zero_leak" and mine_checked and not value.get("checked")):
            continue
        if key in {"provider", "model"} and data.get(key):
            continue
        data[key] = value
    data["attestation_digest"] = attestation.digest()
    return data
