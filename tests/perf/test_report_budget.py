"""Time budgets of the report renderers and of the Demo 1 run (E13-03).

A report of 50 findings renders as HTML in under 5 s and as a PDF in under 20 s; the whole demo
runs in under 3 minutes on a CI runner. The budgets scale with ``CODEKAVACH_PERF_FACTOR`` and the
PDF case is skipped where WeasyPrint's system libraries are absent. Skipped with
``CODEKAVACH_SKIP_PERF=1``.
"""

import os
import time
from pathlib import Path

import pytest

from codekavach.cli.demo_runner import run_demo
from codekavach.core.models.ids import new_finding_id
from codekavach.report.model.build import build_report_document
from codekavach.report.model.document import ReportDocument
from codekavach.report.render.html import HtmlRenderer
from codekavach.report.render.pdf import PdfRenderer, PdfUnavailableError
from tests.support.factories import make_finding, make_scan
from tests.support.kavachbank import FIXTURE_ROOT
from tests.support.perf import assert_within_budget

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(
        os.environ.get("CODEKAVACH_SKIP_PERF") == "1", reason="CODEKAVACH_SKIP_PERF"
    ),
]
FINDINGS = 50
HTML_SECONDS = 5.0
PDF_SECONDS = 20.0
DEMO_SECONDS = 180.0


def _document() -> ReportDocument:
    findings = [make_finding(id=new_finding_id()) for _ in range(FINDINGS)]
    return build_report_document(make_scan(), findings)


def test_fifty_findings_render_as_html_within_budget(tmp_path: Path) -> None:
    document = _document()
    started = time.perf_counter()
    HtmlRenderer().render(document, tmp_path / "report.html")
    assert_within_budget(time.perf_counter() - started, HTML_SECONDS, label="50-finding HTML")


def test_fifty_findings_render_as_pdf_within_budget(tmp_path: Path) -> None:
    document = _document()
    started = time.perf_counter()
    try:
        PdfRenderer().render(document, tmp_path / "report.pdf")
    except PdfUnavailableError:
        pytest.skip("WeasyPrint or its system libraries are not installed")
    assert_within_budget(time.perf_counter() - started, PDF_SECONDS, label="50-finding PDF")


def test_the_demo_runs_within_budget(tmp_path: Path) -> None:
    started = time.perf_counter()
    run_demo(str(FIXTURE_ROOT), tmp_path / "out")
    assert_within_budget(time.perf_counter() - started, DEMO_SECONDS, label="the demo")
