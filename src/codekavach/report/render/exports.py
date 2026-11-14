"""Machine-readable exports: SARIF 2.1.0, JSON, CSV and Markdown.

Owning epic: E31 (E31-03).

Every export reads the finding views of the document, so evidence is already masked and the
report identifiers, ratings and mappings agree with the HTML and PDF. Each format closes its own
injection trap: CSV cells that a spreadsheet would read as a formula are prefixed with a quote,
Markdown neutralises mentions, pipes and HTML, and SARIF respects GitHub's result cap. Output is
deterministic: keys are sorted where order carries no meaning and no timestamp other than the
document's own is written.
"""

import csv
import io
import json
import re
from pathlib import Path
from typing import Any, Final

from codekavach import __version__
from codekavach.report.model.document import ReportDocument
from codekavach.report.model.finding_view import FindingView
from codekavach.report.model.library import OWASP_2021, cwe_name, cwe_url
from codekavach.report.render.theme import Theme

SARIF_SCHEMA: Final = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI: Final = "https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET"
MAX_SARIF_RESULTS: Final = 5_000
JSON_SCHEMA_ID: Final = "codekavach.report/v1"
MARKDOWN_LIMIT: Final = 60_000
_LEVEL: Final = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SEVERITY_SCORE: Final = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}
_IMPORTANCE: Final = {"source": "essential", "sink": "essential", "sanitiser": "important"}
_SUPPRESSED: Final = frozenset({"false_positive", "accepted_risk", "suppressed"})
_FORMULA: Final = ("=", "+", "-", "@", "\t", "\r")


def _write(out: Path, text: str) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", newline="\n")
    return out


# ---------------------------------------------------------------------------------------- SARIF


def _rule_id(view: FindingView) -> str:
    return view.rule_id or (f"CWE-{view.cwe[0]}" if view.cwe else "codekavach.finding")


def _security_severity(view: FindingView) -> str:
    score = view.rating.cvss4_score
    if score is None:
        score = view.rating.cvss31_score
    if score is None:
        score = _SEVERITY_SCORE.get(view.severity, 0.0)
    return f"{score:.1f}"


def _region(line: int) -> dict[str, int]:
    return {"startLine": max(line, 1)}


def build_sarif(doc: ReportDocument) -> dict[str, Any]:  # noqa: PLR0912
    """The SARIF 2.1.0 log of ``doc``: one run, rules, CWE and OWASP taxonomies, code flows."""
    views = sorted(doc.views, key=lambda v: (-v.severity_rank, v.report_id))[:MAX_SARIF_RESULTS]
    rules: dict[str, dict[str, Any]] = {}
    cwes: dict[int, None] = {}
    owasp: dict[str, None] = {}
    for view in views:
        for c in view.cwe:
            cwes.setdefault(c)
        for item in view.owasp:
            owasp.setdefault(item.clause)
    cwe_index = {c: i for i, c in enumerate(sorted(cwes))}
    owasp_index = {o: i for i, o in enumerate(sorted(owasp))}
    results: list[dict[str, Any]] = []
    for view in views:
        rule_id = _rule_id(view)
        if rule_id not in rules:
            relationships = [
                {
                    "target": {
                        "id": f"CWE-{c}",
                        "index": cwe_index[c],
                        "toolComponent": {"name": "CWE", "index": 0},
                    },
                    "kinds": ["superset"],
                }
                for c in view.cwe
            ]
            rules[rule_id] = {
                "id": rule_id,
                "name": re.sub(r"[^A-Za-z0-9]+", "", view.cwe_names[0].title())
                if view.cwe_names
                else "Finding",
                "shortDescription": {"text": view.title},
                "fullDescription": {"text": view.description},
                "help": {
                    "text": f"{view.remediation_short_term}\n\n{view.remediation_long_term}",
                    "markdown": f"**Fix now.** {md_prose(view.remediation_short_term)}\n\n"
                    f"**Prevent recurrence.** {md_prose(view.remediation_long_term)}",
                },
                "helpUri": cwe_url(view.cwe[0]) if view.cwe else INFORMATION_URI,
                "defaultConfiguration": {"level": _LEVEL.get(view.severity, "note")},
                "properties": {
                    "tags": sorted(
                        {"security", *(f"CWE-{c}" for c in view.cwe)}
                        | {f"OWASP-{o.clause}" for o in view.owasp}
                    ),
                    "security-severity": _security_severity(view),
                    "precision": {"high": "high", "medium": "medium"}.get(view.confidence, "low"),
                },
            }
            if relationships:
                rules[rule_id]["relationships"] = relationships
        rule_index = list(rules).index(rule_id)
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": view.primary_path, "uriBaseId": "%SRCROOT%"},
                "region": _region(view.primary_line),
            }
        }
        if view.symbol:
            location["logicalLocations"] = [{"name": view.symbol, "kind": "function"}]
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": _LEVEL.get(view.severity, "note"),
            "message": {"text": f"{view.report_id}: {view.title}"},
            "locations": [location],
            "partialFingerprints": {
                "codekavachFingerprint/v1": view.fingerprint,
                "codekavachReportId/v1": view.report_id,
            },
            "properties": {
                "report_id": view.report_id,
                "severity": view.severity,
                "security-severity": _security_severity(view),
                "confidence": view.confidence,
                "status": view.status,
                "likelihood": view.likelihood,
                "impact": view.impact_level,
                "risk_score": view.risk_score,
                "detected_by": list(view.detected_by),
                "privacy_level": doc.privacy_attestation.default_level
                if doc.privacy_attestation
                else str(doc.scan.privacy_level.value),
            },
        }
        props = result["properties"]
        if view.rating.cvss4_vector:
            props["cvss4_vector"] = view.rating.cvss4_vector
            props["cvss4_score"] = view.rating.cvss4_score
        if view.rating.cvss31_vector:
            props["cvss31_vector"] = view.rating.cvss31_vector
        if view.verdict:
            props["llm_provider"] = view.verdict.provider
            props["llm_model"] = view.verdict.model
            props["llm_is_vulnerable"] = view.verdict.is_vulnerable
        taxa = [
            {"id": f"CWE-{c}", "index": cwe_index[c], "toolComponent": {"name": "CWE", "index": 0}}
            for c in view.cwe
        ] + [
            {
                "id": o.clause,
                "index": owasp_index[o.clause],
                "toolComponent": {"name": "OWASP Top 10", "index": 1},
            }
            for o in view.owasp
        ]
        if taxa:
            result["taxa"] = taxa
        if view.flow:
            result["codeFlows"] = [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": step.path,
                                                "uriBaseId": "%SRCROOT%",
                                            },
                                            "region": _region(step.line),
                                        },
                                        "message": {
                                            "text": f"{step.role}"
                                            + (f": {step.note}" if step.note else "")
                                        },
                                    },
                                    "nestingLevel": 0,
                                    "importance": _IMPORTANCE.get(step.role, "unimportant"),
                                }
                                for step in view.flow
                            ]
                        }
                    ]
                }
            ]
        if view.status in _SUPPRESSED:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": f"Status set to {view.status} in CodeKavach",
                }
            ]
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeKavach",
                        "version": doc.scan.codekavach_version or __version__,
                        "semanticVersion": "0.1.0",
                        "informationUri": INFORMATION_URI,
                        "rules": list(rules.values()),
                        "supportedTaxonomies": [
                            {"name": "CWE", "index": 0},
                            {"name": "OWASP Top 10", "index": 1},
                        ],
                    }
                },
                "taxonomies": [
                    {
                        "name": "CWE",
                        "version": "4.15",
                        "organization": "MITRE",
                        "informationUri": "https://cwe.mitre.org/",
                        "shortDescription": {"text": "Common Weakness Enumeration"},
                        "taxa": [
                            {
                                "id": f"CWE-{c}",
                                "name": cwe_name(c),
                                "helpUri": cwe_url(c),
                            }
                            for c in sorted(cwes)
                        ],
                    },
                    {
                        "name": "OWASP Top 10",
                        "version": "2021",
                        "organization": "OWASP",
                        "informationUri": "https://owasp.org/Top10/",
                        "shortDescription": {"text": "OWASP Top 10 Web Application Risks"},
                        "taxa": [{"id": o, "name": OWASP_2021.get(o, o)} for o in sorted(owasp)],
                    },
                ],
                "automationDetails": {"id": f"codekavach/{doc.scan.id}"},
                "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Project root"}}},
                "results": results,
                "properties": {
                    "report_id": doc.report_id,
                    "truncated": len(doc.views) > MAX_SARIF_RESULTS,
                },
            }
        ],
    }


class SarifRenderer:
    """SARIF 2.1.0 for GitHub code scanning, DefectDojo and IDEs."""

    format = "sarif"
    extension = "sarif"
    binary = False

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``."""
        return _write(out, json.dumps(build_sarif(doc), indent=2, ensure_ascii=False) + "\n")


# ----------------------------------------------------------------------------------------- JSON


def build_json(doc: ReportDocument) -> dict[str, Any]:
    """The stable, versioned JSON report."""
    att = doc.privacy_attestation
    return {
        "schema": JSON_SCHEMA_ID,
        "report": {
            "id": doc.report_id,
            "version": doc.version,
            "title": doc.title,
            "project": doc.project_name,
            "prepared_by": doc.organisation,
            "prepared_for": doc.prepared_for,
            "classification": doc.classification,
            "generated_at": doc.generated_at.isoformat(),
        },
        "scan": {
            "id": str(doc.scan.id),
            "started_at": doc.scan.started_at.isoformat(),
            "finished_at": doc.scan.finished_at.isoformat() if doc.scan.finished_at else None,
            "privacy_level": str(doc.scan.privacy_level.value),
            "provider": doc.scan.provider,
            "model": doc.scan.model,
            "codekavach_version": doc.scan.codekavach_version,
            "config_hash": doc.scan.config_hash,
            "git_commit": doc.scan.git_commit,
        },
        "summary": doc.facts.model_dump(mode="json") if doc.facts else None,
        "executive_summary": [block.model_dump(mode="json") for block in doc.executive],
        "roadmap": [item.model_dump(mode="json") for item in doc.roadmap],
        "findings": [view.model_dump(mode="json") for view in doc.views],
        "coverage": doc.coverage.model_dump(mode="json"),
        "privacy_attestation": None
        if att is None
        else {
            **att.model_dump(mode="json"),
            "zero_leak": {
                "checked": att.zero_leak.checked,
                "terms_checked": att.zero_leak.terms_checked,
                "occurrences": att.zero_leak.occurrences,
                "passed": att.zero_leak.passed,
            },
        },
        "limitations": [item.model_dump(mode="json") for item in doc.limitations],
        "tools": [tool.model_dump(mode="json") for tool in doc.methodology.tools],
    }


class JsonRenderer:
    """The full report as versioned JSON."""

    format = "json"
    extension = "json"
    binary = False

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``."""
        return _write(out, json.dumps(build_json(doc), indent=2, ensure_ascii=False) + "\n")


# ------------------------------------------------------------------------------------------ CSV

CSV_COLUMNS: Final = (
    "report_id",
    "severity",
    "title",
    "status",
    "confidence",
    "cwe",
    "owasp",
    "asvs",
    "cvss4_score",
    "cvss4_vector",
    "cvss31_score",
    "cvss31_vector",
    "likelihood",
    "impact",
    "risk_score",
    "risk_band",
    "priority",
    "file",
    "line",
    "symbol",
    "rule",
    "model_verdict",
    "remediation",
    "compliance",
    "fingerprint",
)


def safe_cell(value: object) -> str:
    """A cell value a spreadsheet will not evaluate as a formula (CWE-1236)."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA):
        return "'" + text
    return text


def finding_row(view: FindingView) -> list[str]:
    """One row of ``CSV_COLUMNS`` for ``view``."""
    values: list[object] = [
        view.report_id,
        view.severity,
        view.title,
        view.status,
        view.confidence,
        "; ".join(f"CWE-{c}" for c in view.cwe),
        "; ".join(o.clause for o in view.owasp),
        "; ".join(view.asvs),
        view.rating.cvss4_score,
        view.rating.cvss4_vector,
        view.rating.cvss31_score,
        view.rating.cvss31_vector,
        view.likelihood,
        view.impact_level,
        view.risk_score,
        view.risk_band,
        view.priority,
        view.primary_path,
        view.primary_line,
        view.symbol,
        view.rule_id,
        view.verdict.label if view.verdict else "",
        view.remediation_short_term,
        "; ".join(f"{c.framework} {c.clause}" for c in view.compliance),
        view.fingerprint,
    ]
    return [safe_cell(value) for value in values]


class CsvRenderer:
    """One row per finding, for trackers and regulator finding tables."""

    format = "csv"
    extension = "csv"
    binary = False

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``."""
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(CSV_COLUMNS)
        for view in doc.views:
            writer.writerow(finding_row(view))
        return _write(out, buffer.getvalue())


# ------------------------------------------------------------------------------------- Markdown


def md(text: object) -> str:
    """``text`` safe inside Markdown: no mentions, no HTML, no table breaks, one line."""
    value = "" if text is None else str(text)
    value = value.replace("\r", " ").replace("\n", " ")
    value = (
        value.replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
    )
    value = value.replace("`", "'")
    return re.sub(r"@(?=\w)", "@\u200b", value)


def md_prose(text: object) -> str:
    """:func:`md` for prose outside code spans: also no Markdown links or images.

    Remediation text can carry model output that scanned code steers; escaping ``[``, ``]``
    and ``!`` keeps ``[fix](https://evil)`` and ``![](beacon)`` as literal text.
    """
    return re.sub(r"([\[\]!])", r"\\\1", md(text))


def build_markdown(doc: ReportDocument, *, limit: int = MARKDOWN_LIMIT) -> str:
    """The Markdown summary: posture, counts, findings table, top details, attestation."""
    facts = doc.facts
    lines = [
        f"# {md(doc.title)}: {md(doc.project_name)}",
        "",
        f"**Report** {md(doc.report_id)} · **Classification** {md(doc.classification)} · "
        f"**Generated** {doc.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    if doc.scan_reference:
        # The id the dashboard shows, so a reader can tie the file to the scan it came from.
        lines += [f"**Scan** {md(doc.scan_reference)} (pipeline {md(str(doc.scan.id))})", ""]
    if facts:
        lines += [
            f"**Overall risk: {facts.posture}** · {facts.total} findings",
            "",
            "| Critical | High | Medium | Low | Info |",
            "|---:|---:|---:|---:|---:|",
            "| " + " | ".join(str(count) for _, count in facts.by_severity) + " |",
            "",
        ]
    lines.append("## Executive summary")
    lines.append("")
    for block in doc.executive:
        if block.id != "overview":
            lines += [f"### {md(block.heading)}", ""]
        lines += [md(p) + "\n" for p in block.paragraphs]
        lines += [f"- {md(item)}" for item in block.bullets]
        lines.append("")
    lines += [
        "## Findings",
        "",
        "| ID | Severity | Title | CWE | Location | Status |",
        "|---|---|---|---|---|---|",
    ]
    lines += [
        f"| {md(v.report_id)} | {v.severity} | {md(v.title)} | {md(v.cwe_label)} | "
        f"`{md(v.location_label)}` | {md(v.status)} |"
        for v in doc.views
    ]
    lines.append("")
    if doc.roadmap:
        lines += ["## Remediation roadmap", "", "| Priority | Timeline | Action | Findings |"]
        lines.append("|---|---|---|---|")
        lines += [
            f"| {r.priority} | {md(r.lane)} ({md(r.window)}) | {md(r.action)} | "
            f"{md(', '.join(r.report_ids))} |"
            for r in doc.roadmap
        ]
        lines.append("")
    details = ["## Finding details", ""]
    for v in doc.views:
        entry = [
            f"### {md(v.report_id)}: {md(v.title)}",
            "",
            f"- **Severity:** {v.severity} · **Risk:** {v.risk_score} ({v.risk_band}) · "
            f"**Confidence:** {v.confidence}",
            f"- **CWE:** {md(v.cwe_label)} · **OWASP:** {md(v.owasp_label)}",
            f"- **Location:** `{md(v.location_label)}`",
            f"- **Remediation:** {md_prose(v.remediation_short_term)}",
        ]
        if v.verdict:
            entry.append(f"- **Model assessment:** {md(v.verdict.label)} ({md(v.verdict.model)})")
        entry.append("")
        details += entry
    att = doc.privacy_attestation
    tail = []
    if att:
        tail = [
            "## Privacy attestation",
            "",
            f"- Privacy level: {md(att.default_level)}; provider {md(att.provider or 'none')} / "
            f"{md(att.model or 'none')}",
            f"- Ledger entries: {att.ledger_entries}; sent {att.requests_sent}, blocked "
            f"{att.requests_blocked}",
            f"- Ledger head: `{md(att.ledger_head_hash or 'none')}`; chain {md(att.chain_text)}",
            f"- Zero-leak check: {md(att.zero_leak.text)}",
            "",
        ]
    body = "\n".join(lines)
    tail_text = "\n".join(tail)
    remaining = limit - len(body) - len(tail_text) - 200
    detail_text = ""
    for chunk in "\n".join(details).split("\n### "):
        piece = chunk if not detail_text else "\n### " + chunk
        if len(detail_text) + len(piece) > remaining:
            detail_text += "\n\n_Further details omitted to keep this summary short; see the full "
            detail_text += "HTML or PDF report._\n"
            break
        detail_text += piece
    return body + "\n" + detail_text + "\n" + tail_text + "\n"


class MarkdownRenderer:
    """A size-capped Markdown summary for pull requests and job summaries."""

    format = "markdown"
    extension = "md"
    binary = False

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``."""
        return _write(out, build_markdown(doc))


class MdRenderer(MarkdownRenderer):
    """The Markdown summary under the short format name ``md``."""

    format = "md"
