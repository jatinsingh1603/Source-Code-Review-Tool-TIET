"""The report document, the renderer registry and the HTML renderer (E13-03)."""

import re
from pathlib import Path

import pytest

from codekavach.config import Settings
from codekavach.core.models.enums import Severity
from codekavach.core.models.finding import Finding
from codekavach.report.model import build_report_document
from codekavach.report.model.build import LedgerSummary
from codekavach.report.model.document import ReportDocument, ZeroLeak
from codekavach.report.render import renderer_registry
from codekavach.report.render.html import HtmlRenderer, render_html, running_header
from codekavach.report.render.pdf import PdfRenderer, PdfUnavailableError, _refuse
from tests.support.factories import make_finding, make_scan

HOSTILE = (
    '<script>alert(1)</script> <img src="https://evil.example/x.png"> '
    '<a href="data:text/html;base64,PHNjcmlwdD4=">go</a> {{ 7 * 7 }}'
)
EXTERNAL = re.compile(
    r"""(?:src|href|action|poster|data)\s*=\s*["']?\s*(?:https?:|//|data:|ftp:)"""
    r"""|url\(|@import|<link\b|<script\b[^>]*\bsrc|<img\b|<iframe\b|<object\b|<embed\b""",
    re.IGNORECASE,
)


def document(
    findings: tuple[Finding, ...] | None = None,
    settings: Settings | None = None,
    ledger: LedgerSummary | None = None,
) -> ReportDocument:
    items = findings if findings is not None else (make_finding(),)
    return build_report_document(
        make_scan(provider="mock", model="mock-1"), items, settings, ledger
    )


def test_the_page_names_the_finding_with_numbered_snippet_lines() -> None:
    page = render_html(document())
    finding = make_finding()
    assert finding.title in page
    assert str(finding.evidence[0].lines[0].number) in page
    assert 'class="ln hit"' in page
    assert "<pre" in page and "<img" not in page


def test_model_and_client_text_renders_as_inert_text() -> None:
    hostile = make_finding(title="Injection", remediation=HOSTILE, description=HOSTILE)
    page = render_html(document((hostile,)))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;img src=" in page
    assert "data:text/html" in page  # present as text only
    assert "{{ 7 * 7 }}" in page  # a template expression in the data is not evaluated
    assert not EXTERNAL.search(page.replace("data:text/html", "text"))


def test_the_page_has_no_remote_resource_and_a_content_security_policy() -> None:
    page = render_html(document())
    assert not EXTERNAL.search(page)
    assert 'http-equiv="Content-Security-Policy"' in page
    assert "default-src &#39;none&#39;" in page and "form-action &#39;none&#39;" in page
    assert page.count("<script") == 1  # the one inline, packaged script
    script = page[page.index("<script>") : page.index("</script>")]
    for banned in ("innerHTML", "eval(", "Function(", "document.write", "outerHTML"):
        assert banned not in script


def test_snippet_text_is_escaped_even_when_the_source_contains_markup() -> None:
    from codekavach.core.models.enums import Language  # noqa: PLC0415
    from codekavach.core.models.evidence import Evidence  # noqa: PLC0415
    from codekavach.core.models.text import RawCode  # noqa: PLC0415
    from tests.support.factories import make_location  # noqa: PLC0415

    location = make_location(start_line=2, end_line=2)
    source = RawCode('x = 1\nq = "<script>steal()</script>"\ny = 2\n')
    evidence = Evidence.from_source(source, location, language=Language.PYTHON)
    page = render_html(document((make_finding(evidence=(evidence,)),)))
    assert "&lt;script&gt;steal()&lt;/script&gt;" in page
    assert "<script>steal" not in page


def test_the_attestation_holds_every_element() -> None:
    ledger = LedgerSummary(
        head_hash="a" * 64,
        entries=3,
        by_outcome=(("not_sent_dry_run", 3),),
        disclosure=(("repository_fraction_pct", "12.50"), ("files", "4")),
        zero_leak=ZeroLeak(checked=True, terms_checked=9, occurrences=0),
    )
    doc = document(settings=Settings(), ledger=ledger)
    page = render_html(doc)
    attestation = doc.privacy_attestation
    assert attestation is not None
    for expected in (
        "a" * 64,
        "repository fraction pct",
        "12.50",
        "9 listed terms searched in every ledger payload: no occurrence",
        "not_sent_dry_run: 3",
        "mock",
        "Retention",
        "does not cover",
        "would have left the environment",
    ):
        assert expected in page, expected


def test_a_run_that_did_not_check_terms_says_so() -> None:
    page = render_html(document(settings=Settings()))
    assert "not checked in this run" in page


def test_the_attestation_can_be_switched_off() -> None:
    settings = Settings.model_validate({"reporting": {"include_privacy_attestation": False}})
    doc = document(settings=settings)
    assert doc.privacy_attestation is None and "Privacy attestation" not in render_html(doc)


def test_the_running_header_keeps_only_safe_characters() -> None:
    assert running_header('Secret"; } body { x') == "Secret  body  x"
    assert '"' not in running_header('A"B') and "\\" not in running_header(r"A\B")
    assert running_header("") == "Confidential"


def test_the_registry_finds_the_renderers_through_the_entry_point_group() -> None:
    registry = renderer_registry()
    assert {"html", "pdf"} <= set(registry.names())
    assert isinstance(registry.get("html"), HtmlRenderer)
    assert isinstance(registry.get("pdf"), PdfRenderer)
    with pytest.raises(KeyError):
        registry.get("nonexistent")


def test_the_html_renderer_writes_one_self_contained_file(tmp_path: Path) -> None:
    out = HtmlRenderer().render(document(), tmp_path / "nested" / "report.html")
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert [item.name for item in out.parent.iterdir()] == ["report.html"]


def test_findings_are_listed_most_severe_first() -> None:
    low = make_finding(severity=Severity.LOW, title="Minor issue")
    high = make_finding(severity=Severity.CRITICAL, title="Major issue")
    page = render_html(document((low, high)))
    assert page.index("Major issue") < page.index("Minor issue")


def test_the_pdf_renderer_writes_a_pdf_or_reports_the_engine_missing(tmp_path: Path) -> None:
    try:
        out = PdfRenderer().render(document(), tmp_path / "report.pdf")
    except PdfUnavailableError:
        pytest.skip("WeasyPrint or its system libraries are not installed")
    assert out.read_bytes().startswith(b"%PDF")


def test_the_pdf_fetcher_refuses_every_url() -> None:
    for url in ("https://evil.example/x.css", "file:///etc/passwd", "data:text/css,a{}"):
        with pytest.raises(ValueError, match="no external resource"):
            _refuse(url)
