"""The self-contained HTML report.

Owning epic: E13. MVP; extended by E31, which adds themes, the full section set and more formats.

Output handling is a security control here: both the client's code and the model's text are
attacker-influenced (``docs/research/INSIGHTS.md`` section 7). Autoescaping is on for every value,
the template never marks model or client text safe, nothing is linkified, the page loads no remote
resource of any kind, and a content-security policy meta tag forbids the browser to fetch one. A
snippet is text with line numbers and marked lines, never an image.
"""

from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Final

from jinja2 import Environment, FunctionLoader, StrictUndefined, select_autoescape
from markupsafe import Markup, escape

from codekavach.core.models.enums import Severity
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import Finding
from codekavach.report.model.document import ReportDocument

TEMPLATE: Final = "report.html.j2"
CSP: Final = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'"
SEVERITIES: Final = tuple(reversed(list(Severity)))
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


def _matrix(document: ReportDocument) -> dict[tuple[int, int], int]:
    return {
        (likelihood, impact): count for likelihood, impact, count in document.summary.risk_matrix
    }


def render_html(document: ReportDocument) -> str:
    """The page for ``document`` as one string."""
    findings: tuple[Finding, ...] = document.findings
    context: dict[str, Any] = {
        "doc": document,
        "findings": findings,
        "csp": CSP,
        "header": running_header(document.classification),
        "matrix": _matrix(document),
        "by_severity": dict(document.summary.by_severity),
        "by_status": dict(document.summary.by_status),
        "attestation": document.privacy_attestation,
    }
    return environment().get_template(TEMPLATE).render(**context)


class HtmlRenderer:
    """Writes the report as one HTML file with its stylesheet inline."""

    format = "html"
    extension = "html"

    def render(self, doc: ReportDocument, out: Path) -> Path:
        """Write ``doc`` to ``out``."""
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_html(doc), encoding="utf-8", newline="\n")
        return out
