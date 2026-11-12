"""The self-contained, interactive HTML audit report (and the HTML the PDF is printed from).

Owning epic: E13. MVP; extended by E31 (E31-02): cover, document control, executive summary,
scope, methodology, rating method, charts, detailed findings with filters, roadmap, privacy
attestation and appendices, with dark mode and print styles.

Output handling is a security control here: both the client's code and the model's text are
attacker-influenced (``docs/research/INSIGHTS.md`` section 7). Autoescaping is on for every value,
the template never marks model or client text safe, nothing is linkified, the page loads no remote
resource of any kind, and a content-security policy meta tag forbids the browser to fetch one. The
report template runs in a sandboxed environment; its only inline script reads data attributes
and never builds markup. A snippet is text with line numbers and marked lines, never an image.
"""

from collections import Counter
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Final

from jinja2 import Environment, FunctionLoader, StrictUndefined, select_autoescape
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup, escape

from codekavach.core.models.enums import Severity
from codekavach.core.models.evidence import Evidence
from codekavach.report.model.document import ReportDocument
from codekavach.report.render.charts import bar_chart, donut, risk_matrix, severity_chart
from codekavach.report.render.snippets import css_rules, token_rows
from codekavach.report.render.theme import DEFAULT_THEME, Theme

# The inspection page (cli.inspect_page) keeps the stricter policy: it has no script and no image.
CSP: Final = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'"
SEVERITIES: Final = tuple(reversed(list(Severity)))
SEVERITY_NAMES: Final = tuple(item.value for item in SEVERITIES)
_SAFE_MARKING = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -/.,")


@dataclass(frozen=True)
class SnippetRow:
    """One numbered line of a snippet; ``html`` is escaped, with ``<mark>`` around highlights."""

    number: int
    html: Markup
    marked: bool


def _template_source(name: str) -> str:
    return resources.files("codekavach.report.templates").joinpath(name).read_text(encoding="utf-8")


def _row(evidence: Evidence, line_number: int, text: str) -> Markup:
    pieces: list[Markup | str] = []
    cursor = 0
    for highlight in evidence.highlights:
        if highlight.line != line_number:
            continue
        start, end = max(highlight.start_col - 1, cursor), max(highlight.end_col - 1, cursor)
        pieces.append(escape(text[cursor:start]))
        pieces.append(Markup("<mark>{}</mark>").format(text[start:end]))
        cursor = end
    pieces.append(escape(text[cursor:]))
    return Markup("").join(pieces)


def snippet_rows(evidence: Evidence) -> list[SnippetRow]:
    """The rows of ``evidence``: line number, escaped text and whether it is a finding line."""
    location = evidence.location
    return [
        SnippetRow(
            number=line.number,
            html=_row(evidence, line.number, line.text.expose()),
            marked=location.start_line <= line.number <= location.end_line,
        )
        for line in evidence.lines
    ]


def running_header(classification: str) -> str:
    """The classification marking as safe CSS string content: letters, digits and a few marks."""
    cleaned = "".join(char for char in classification if char in _SAFE_MARKING).strip()
    return cleaned[:60] or "Confidential"


def environment() -> Environment:
    """The Jinja2 environment: autoescape on for every template, strict about missing values."""
    env = Environment(
        loader=FunctionLoader(_template_source),
        autoescape=select_autoescape(default=True, default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["snippet_rows"] = snippet_rows
    env.globals["severities"] = SEVERITIES
    return env


REPORT_TEMPLATE: Final = "html/report.html.j2"
REPORT_CSP: Final = (
    "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "base-uri 'none'; form-action 'none'"
)
LIKELIHOOD_TEXT: Final = {
    1: "rare; requires unusual conditions or insider access.",
    2: "unlikely; requires authentication and specific conditions.",
    3: "possible; reachable by an authenticated user.",
    4: "likely; reachable from the network with little effort.",
    5: "almost certain; reachable anonymously and trivially exploitable.",
}


@dataclass(frozen=True)
class ComplianceRow:
    """One control of the compliance annex and the findings that are evidence against it."""

    framework: str
    clause: str
    title: str | None
    ids: tuple[str, ...]


def compliance_rows(document: ReportDocument) -> list[ComplianceRow]:
    """The compliance annex: one row per (framework, clause), findings in report order."""
    rows: dict[tuple[str, str], tuple[str | None, list[str]]] = {}
    for view in document.views:
        for item in (*view.owasp, *view.compliance):
            key = (item.framework, item.clause)
            _title, ids = rows.setdefault(key, (item.title, []))
            if view.report_id not in ids:
                ids.append(view.report_id)
    return [
        ComplianceRow(framework, clause, title, tuple(ids))
        for (framework, clause), (title, ids) in sorted(rows.items())
    ]


def _css_source(name: str, theme: Theme, **extra: str) -> str:
    """A stylesheet template filled with validated theme values (hex colours, safe font stacks)."""
    env = Environment(autoescape=False, undefined=StrictUndefined)  # noqa: S701 - CSS, validated
    return env.from_string(_template_source(name)).render(
        theme=theme, token_css=css_rules(), **extra
    )


def chart_set(document: ReportDocument, theme: Theme) -> dict[str, Markup]:
    """The report's charts as inline SVG, generated from the finding views."""
    facts = document.facts
    counts = list(facts.by_severity) if facts else [(name, 0) for name in SEVERITY_NAMES]
    cells: Counter[tuple[int, int]] = Counter(
        (view.likelihood, view.impact_level) for view in document.views
    )
    cwe_rows = [(name, count, theme.brand) for name, count in (facts.top_cwes if facts else ())]
    owasp_rows = [(name, count, theme.accent) for name, count in (facts.top_owasp if facts else ())]
    return {
        "donut": Markup(donut(counts, theme=theme)),  # noqa: S704 - generated, text escaped
        "severity": Markup(severity_chart(counts, theme=theme)),  # noqa: S704
        "matrix": Markup(risk_matrix(dict(cells), theme=theme)),  # noqa: S704
        "cwe": Markup(bar_chart(cwe_rows, title="Top CWE", theme=theme)),  # noqa: S704
        "owasp": Markup(bar_chart(owasp_rows, title="OWASP Top 10", theme=theme)),  # noqa: S704
    }


def _toc(document: ReportDocument) -> list[tuple[str, str]]:
    toc = [
        ("executive", "Executive summary"),
        ("scope", "Scope and approach"),
        ("methodology", "Methodology"),
        ("rating", "Risk rating method"),
        ("summary", "Summary of findings"),
        ("findings", "Detailed findings"),
        ("roadmap", "Remediation roadmap"),
    ]
    if document.privacy_attestation is not None:
        toc.append(("privacy", "Privacy attestation"))
    toc.append(("appendix", "Appendices"))
    return toc


def report_environment() -> Environment:
    """The sandboxed, autoescaping environment of the audit report template."""
    env = SandboxedEnvironment(
        loader=FunctionLoader(_template_source),
        autoescape=select_autoescape(default=True, default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals["snippet_rows"] = token_rows
    env.globals["zip"] = zip
    env.globals["likelihood_text"] = LIKELIHOOD_TEXT
    return env


def render_html(document: ReportDocument, *, pdf: bool = False, theme: Theme | None = None) -> str:
    """The audit report page for ``document`` as one string; ``pdf`` selects the paged layout."""
    chosen = theme or DEFAULT_THEME
    header = running_header(document.classification).upper()
    footer = running_header(f"{document.report_id} {document.project_name}")
    css = _css_source("html/report.css", chosen)
    if pdf:
        css += _css_source("html/pdf.css", chosen, header=header, footer=footer)
    else:
        css += _css_source("html/screen.css", chosen)
    views = document.views
    context: dict[str, Any] = {
        "doc": document,
        "views": views,
        "pdf": pdf,
        "csp": REPORT_CSP,
        "css": Markup(css),  # noqa: S704 - generated from validated theme values
        "script": Markup(_template_source("html/report.js")),  # noqa: S704 - packaged script
        "charts": chart_set(document, chosen),
        "toc": _toc(document),
        "statuses": sorted({view.status for view in views}),
        "cwes": sorted({c for view in views for c in view.cwe}),
        "compliance": compliance_rows(document),
    }
    return report_environment().get_template(REPORT_TEMPLATE).render(**context)


class HtmlRenderer:
    """Writes the report as one self-contained, interactive HTML file."""

    format = "html"
    extension = "html"
    binary = False

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``."""
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_html(doc, theme=theme), encoding="utf-8", newline="\n")
        return out
