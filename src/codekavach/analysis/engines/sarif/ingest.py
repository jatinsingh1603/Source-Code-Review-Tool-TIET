"""The entry point of SARIF reading: a log in, ``Candidate`` objects out (E14-02).

Owning epic: E14. Every adapter whose engine speaks SARIF calls ``ingest_sarif`` (or
``ingest_engine_run``) from ``EngineAdapter.parse``.

What a candidate gets:

* locations resolved against the scan root (``locations``), checked against the real file, so a
  result that names a file outside the root, or one that is not there, yields no candidate;
* CWE, severity and confidence by the table-driven rules of ``cwe`` and ``severity``;
* a ``ckfp1`` fingerprint computed here from the real file lines. Engine-supplied partial
  fingerprints are kept as ``sarif.partial_fingerprint.*`` properties and are never trusted as
  identity; CodeKavach's own key (``codekavachFingerprint/v1``) is ignored on the way in;
* a taint path when a code flow validates and its sink file is one of the locations;
* suppressions carried in ``sarif.suppressed``. Nothing suppressed is dropped here (E21 decides).

``region.snippet`` is never read, so no engine-quoted code enters a candidate. A secret candidate
takes the rule's description for its message and keeps no engine properties, because an engine may
quote the secret in its own result.
"""

import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from codekavach.analysis.engines.base import CodeFlowOrder, EngineRun, EngineSpec
from codekavach.analysis.engines.sarif.codeflows import code_flow_to_taint_path
from codekavach.analysis.engines.sarif.cwe import extract_cwe_details
from codekavach.analysis.engines.sarif.errors import SarifFormatError, SarifSizeError
from codekavach.analysis.engines.sarif.locations import (
    SourceCache,
    region_to_location,
    resolve_uri,
)
from codekavach.analysis.engines.sarif.model import (
    Location as SarifLocation,
)
from codekavach.analysis.engines.sarif.model import (
    ReportingDescriptor,
    Result,
    Run,
    SarifLog,
)
from codekavach.analysis.engines.sarif.rules import RuleIndex
from codekavach.analysis.engines.sarif.severity import normalise_confidence, normalise_severity
from codekavach.analysis.engines.sarif.tables import CweFallback, SeverityTable
from codekavach.analysis.engines.sarif.textutil import clean_text
from codekavach.core.log import get_logger
from codekavach.core.models.candidate import (
    MAX_MESSAGE_LENGTH,
    MAX_PROPERTIES,
    MAX_PROPERTY_VALUE_LENGTH,
    Candidate,
)
from codekavach.core.models.enums import CandidateKind
from codekavach.core.models.fingerprint import (
    MAX_SNIPPET_LINES,
    SARIF_PARTIAL_FINGERPRINT_KEY,
    FingerprintParts,
    fingerprint_batch,
    snippet_hash,
)
from codekavach.core.models.location import Location
from codekavach.ingest.langdetect import detect_language

DEFAULT_MAX_BYTES: Final = 64 * 1024 * 1024
MAX_LOCATIONS: Final = 16
MAX_PROBLEMS: Final = 50
PARTIAL_PREFIX: Final = "sarif.partial_fingerprint."
_NOT_FINDINGS: Final = frozenset({"pass", "notApplicable"})
_KIND_TAGS: Final = {
    "secret": CandidateKind.SECRET,
    "secrets": CandidateKind.SECRET,
    "dependency": CandidateKind.DEPENDENCY,
    "misconfiguration": CandidateKind.MISCONFIGURATION,
    "hotspot": CandidateKind.HOTSPOT,
    "security-hotspot": CandidateKind.HOTSPOT,
}
_FUNCTION_KINDS: Final = frozenset({"function", "method", "member"})
_INVALID_KEY = re.compile(r"[^a-z0-9_.-]")
_SECRET_FALLBACK_MESSAGE: Final = "Possible hard-coded secret"  # noqa: S105 - a fixed phrase

_log = get_logger(__name__)


@dataclass(frozen=True)
class IngestOptions:
    """What an adapter can tune about a conversion; the defaults suit a plain SARIF engine."""

    code_flow_order: CodeFlowOrder = "source_first"
    default_kind: CandidateKind = CandidateKind.VULNERABILITY
    max_bytes: int = DEFAULT_MAX_BYTES
    cwe_fallback: CweFallback | None = None
    severity_table: SeverityTable | None = None


def _problems(data: object) -> list[str]:
    if not isinstance(data, dict):
        return ["the log is not a JSON object"]
    problems: list[str] = []
    if "version" not in data:
        problems.append("missing version")
    runs = data.get("runs")
    if not isinstance(runs, list):
        problems.append("missing runs")
        return problems
    for position, run in enumerate(runs):
        problems.extend(_run_problems(position, run))
        if len(problems) >= MAX_PROBLEMS:
            break
    return problems[:MAX_PROBLEMS]


def _run_problems(position: int, run: object) -> list[str]:
    if not isinstance(run, dict):
        return [f"runs[{position}] is not an object"]
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    if not isinstance(driver, dict):
        return [f"runs[{position}] has no tool.driver"]
    rules = driver.get("rules")
    count = len(rules) if isinstance(rules, list) else 0
    results = run.get("results", [])
    if not isinstance(results, list):
        return [f"runs[{position}].results is not a list"]
    problems: list[str] = []
    for number, result in enumerate(results):
        if not isinstance(result, dict):
            problems.append(f"runs[{position}].results[{number}] is not an object")
            continue
        index = result.get("ruleIndex")
        reference = result.get("rule")
        external = isinstance(reference, dict) and reference.get("toolComponent") is not None
        if (
            isinstance(index, int)
            and not isinstance(index, bool)
            and index >= count
            and not external
        ):
            problems.append(f"runs[{position}].results[{number}].ruleIndex {index} has no rule")
        if len(problems) >= MAX_PROBLEMS:
            break
    return problems


def validate_log(text: bytes) -> list[str]:
    """Structural problems of a SARIF log: no version, no runs, a ruleIndex that has no rule.

    The list is empty for a log that can be read. It names positions and never quotes the log.
    """
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return ["the output is not valid JSON"]
    return _problems(data)


def _clean_rule_id(value: str) -> str:
    cleaned = "".join(
        "_" if char.isspace() or unicodedata.category(char) == "Cc" else char for char in value
    )
    return cleaned[:256]


def _property_key(raw: str) -> str:
    return _INVALID_KEY.sub("_", raw.lower())[:64]


def _symbol_of(location: SarifLocation) -> str | None:
    for logical in location.logical_locations:
        if logical.kind in _FUNCTION_KINDS and logical.name:
            return logical.name
    return None


def _kind_of(rule: ReportingDescriptor | None, default: CandidateKind) -> CandidateKind:
    tags = rule.properties.get("tags") if rule else None
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.lower() in _KIND_TAGS:
                return _KIND_TAGS[tag.lower()]
    return default


def _message(result: Result, rule: ReportingDescriptor | None, kind: CandidateKind) -> str:
    described = ""
    if rule is not None:
        description = rule.short_description.text if rule.short_description else None
        described = description or rule.name or ""
    if kind is CandidateKind.SECRET:
        return clean_text(described, MAX_MESSAGE_LENGTH) or _SECRET_FALLBACK_MESSAGE
    text = (result.message.text if result.message else None) or described
    return clean_text(text, MAX_MESSAGE_LENGTH)


def _run_identity(run: Run) -> tuple[str, str | None]:
    driver = run.tool.driver if run.tool else None
    name = (driver.name if driver else None) or "unknown"
    version = (driver.semantic_version or driver.version) if driver else None
    return f"{name}@{version or 'unknown'}", version


@dataclass
class _Pending:
    fields: dict[str, Any]
    parts: FingerprintParts


@dataclass
class _Context:
    engine_id: str
    engine_version: str | None
    root: Path
    options: IngestOptions
    source: SourceCache
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def _locations(result: Result, run: Run, ctx: _Context) -> list[Location]:
    found: list[Location] = []
    reason = "no_location"
    for location in result.locations[:MAX_LOCATIONS]:
        physical = location.physical_location
        if physical is None or physical.artifact_location is None:
            continue
        path = resolve_uri(physical.artifact_location, run, ctx.root)
        if path is None:
            reason = "path_rejected"
            continue
        lines = ctx.source.lines(path)
        if lines is None:
            reason = reason if reason == "path_rejected" else "file_missing"
            continue
        for symbol in (_symbol_of(location), None):
            try:
                found.append(
                    region_to_location(
                        physical.region, path, lines, column_kind=run.column_kind, symbol=symbol
                    )
                )
                break
            except ValueError:
                continue
        else:
            reason = reason if reason == "path_rejected" else "region_outside_file"
    if not found:
        ctx.skip(reason)
    return found


def _properties(
    result: Result,
    kind: CandidateKind,
    extras: list[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    pairs = list(extras)
    if result.suppressions:
        justification = clean_text(result.suppressions[0].justification or "", 500)
        pairs.append(("sarif.suppressed", justification or "true"))
    if kind is not CandidateKind.SECRET:
        pairs.extend(
            (PARTIAL_PREFIX + _property_key(key), str(value))
            for key, value in result.partial_fingerprints.items()
            if key != SARIF_PARTIAL_FINGERPRINT_KEY and not key.startswith("codekavachFingerprint")
        )
    unique: dict[str, str] = {}
    for key, value in pairs:
        unique.setdefault(key, value[:MAX_PROPERTY_VALUE_LENGTH])
    return tuple(unique.items())[:MAX_PROPERTIES]


def _convert(
    result: Result,
    run: Run,
    index: RuleIndex,
    identity: tuple[str, str | None],
    ctx: _Context,
) -> _Pending | None:
    if result.kind in _NOT_FINDINGS:
        ctx.skip("not_a_finding")
        return None
    rule = index.lookup(result)
    raw_rule_id = index.rule_id_of(result, rule)
    if not raw_rule_id:
        ctx.skip("no_rule")
        return None
    rule_id = _clean_rule_id(raw_rule_id)
    locations = _locations(result, run, ctx)
    if not locations:
        return None
    kind = _kind_of(rule, ctx.options.default_kind)
    cwe = extract_cwe_details(
        rule, result, ctx.engine_id, run=run, rule_id=rule_id, fallback=ctx.options.cwe_fallback
    )
    taint = None
    for flow in result.code_flows:
        path = code_flow_to_taint_path(
            flow, run, ctx.root, ctx.source, order=ctx.options.code_flow_order
        )
        if path is None:
            continue
        if path.sink.location.path not in {location.path for location in locations}:
            _log.warning("codeflow_discarded", engine=ctx.engine_id, rule_id=rule_id)
            continue
        taint = path
        break
    extras: list[tuple[str, str]] = []
    if cwe.source:
        extras.append(("cwe.source", cwe.source))
    if cwe.unmapped:
        extras.append(("cwe.unmapped", "pillar"))
    extras.append(("engine.run", identity[0][:MAX_PROPERTY_VALUE_LENGTH]))
    primary = locations[0]
    lines = ctx.source.lines(primary.path) or []
    window = lines[primary.start_line - 1 : min(primary.end_line, primary.start_line + 199)]
    parts = FingerprintParts(
        engine=ctx.engine_id,
        rule_id=rule_id,
        path=primary.path,
        symbol=primary.symbol,
        snippet_hash=snippet_hash(window[: MAX_SNIPPET_LINES * 4]),
        start_line=primary.start_line,
    )
    fields: dict[str, Any] = {
        "rule_id": rule_id,
        "engine": ctx.engine_id,
        "cwe": cwe.cwe,
        "locations": tuple(locations),
        "taint_path": taint,
        "engine_severity": normalise_severity(
            result, rule, ctx.engine_id, table=ctx.options.severity_table, rule_id=rule_id
        ),
        "engine_confidence": normalise_confidence(
            result, rule, ctx.engine_id, table=ctx.options.severity_table
        ),
        "engine_version": (ctx.engine_version or identity[1] or "")[:64] or None,
        "kind": kind,
        "language": detect_language(primary.path, ctx.source.head(primary.path)),
        "message": _message(result, rule, kind),
        "properties": _properties(result, kind, extras),
    }
    return _Pending(fields, parts)


def ingest_sarif(
    text: bytes,
    *,
    engine_id: str,
    root: Path,
    engine_version: str | None,
    options: IngestOptions | None = None,
) -> list[Candidate]:
    """Convert a SARIF 2.1.0 log into candidates.

    ``root`` is the directory the engine scanned (the read-only view): paths are made relative to
    it and each file is read from it. Results that cannot be located inside the root are left out
    and counted in one log event. A log that is not valid raises ``SarifFormatError``; one above
    ``options.max_bytes`` raises ``SarifSizeError``.
    """
    chosen = options or IngestOptions()
    if len(text) > chosen.max_bytes:
        raise SarifSizeError(len(text), chosen.max_bytes)
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise SarifFormatError(["the output is not valid JSON"]) from None
    problems = _problems(data)
    if problems:
        raise SarifFormatError(problems)
    try:
        log = SarifLog.model_validate(data)
    except ValidationError:
        raise SarifFormatError(["the log does not match the SARIF structure"]) from None
    del data
    ctx = _Context(engine_id, engine_version, root, chosen, SourceCache(root))
    pending: list[_Pending] = []
    for run in log.runs or ():
        index = RuleIndex(run)
        identity = _run_identity(run)
        for result in run.results:
            item = _convert(result, run, index, identity, ctx)
            if item is not None:
                pending.append(item)
    fingerprints = fingerprint_batch([item.parts for item in pending])
    candidates = [
        Candidate.create(
            **item.fields,
            fingerprint=fingerprint,
        )
        for item, fingerprint in zip(pending, fingerprints, strict=True)
    ]
    if ctx.skipped:
        _log.warning("sarif_results_skipped", engine=engine_id, reasons=dict(ctx.skipped))
    return candidates


def ingest_engine_run(
    spec: EngineSpec,
    run: EngineRun,
    root: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> list[Candidate]:
    """Read ``run.output_path`` and convert it with the options the engine's spec states."""
    if run.output_path is None:
        raise SarifFormatError(["the engine wrote no output file"])
    size = run.output_path.stat().st_size
    if size > max_bytes:
        raise SarifSizeError(size, max_bytes)
    return ingest_sarif(
        run.output_path.read_bytes(),
        engine_id=spec.id,
        root=root,
        engine_version=run.version or None,
        options=IngestOptions(
            code_flow_order=spec.code_flow_order,
            default_kind=spec.default_kind,
            max_bytes=max_bytes,
        ),
    )
