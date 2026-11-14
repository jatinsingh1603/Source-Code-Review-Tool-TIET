"""Audit model, masking, exports, annex, delta and manifest (E30, E31)."""

import csv
import json
import re
import zipfile
from pathlib import Path

import jsonschema
import pytest

from codekavach.config import Settings
from codekavach.core.models.enums import Language, Severity
from codekavach.core.models.evidence import Evidence
from codekavach.core.models.finding import Finding
from codekavach.core.models.ids import new_finding_id
from codekavach.core.models.text import RawCode
from codekavach.report.model import build_report_document
from codekavach.report.model.document import ReportDocument
from codekavach.report.model.ids import ReportIdScheme, assign_report_ids
from codekavach.report.model.masking import mask_lines
from codekavach.report.render import renderer_registry
from codekavach.report.render.bundle import (
    build_delta,
    render_delta_html,
    verify_manifest,
    write_manifest,
)
from codekavach.report.render.exports import build_markdown, build_sarif, safe_cell
from codekavach.report.render.html import render_html
from tests.support.factories import make_finding as _make_finding
from tests.support.factories import make_location, make_scan

SCHEMA = Path(__file__).parents[2] / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"
FORMATS = ("html", "sarif", "json", "csv", "markdown", "md", "xlsx", "docx", "compliance")


_COUNTER = iter(range(1, 10_000))


def make_finding(**overrides: object) -> Finding:
    """A sample finding with its own id and fingerprint."""
    number = next(_COUNTER)
    overrides.setdefault("id", new_finding_id())
    overrides.setdefault("fingerprint", f"ckfp1:{number:032x}")
    return _make_finding(**overrides)


def _doc(*findings: object) -> ReportDocument:
    items = findings or (
        make_finding(severity=Severity.HIGH, title="SQL built from input", cwe=(89,)),
        make_finding(severity=Severity.LOW, title="Weak hash", cwe=(327,)),
    )
    return build_report_document(
        make_scan(provider="mock", model="mock-1"),
        items,  # type: ignore[arg-type]
        Settings(),
        project_name="KavachBank",
        prepared_for="Example Bank",
    )


def _secret_finding() -> object:
    location = make_location(start_line=2, end_line=2)
    source = RawCode(f'x = 1\naws_key = "{AWS_EXAMPLE}"\npassword = "hunter2-secret"\n')
    evidence = Evidence.from_source(source, location, language=Language.PYTHON)
    return make_finding(evidence=(evidence,), title="Hard-coded credential", cwe=(798,))


def test_docx_renders_xml_invalid_control_characters(tmp_path: Path) -> None:
    pytest.importorskip("docx")
    location = make_location(start_line=2, end_line=2)
    source = RawCode("x = 1\n\x0cq = run('\x1b[31m' + v)\x0b\ny = 2\n")
    evidence = Evidence.from_source(source, location, language=Language.PYTHON)
    doc = _doc(
        make_finding(evidence=(evidence,), title="Ctrl\x1b title", remediation="Fix\x0c now")
    )
    out = renderer_registry().get("docx").render(doc, tmp_path / "r.docx")
    with zipfile.ZipFile(out) as archive:
        body = archive.read("word/document.xml").decode("utf-8")
    assert "Ctrl\ufffd title" in body and "\ufffd[31m" in body
    assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", body)


def test_report_ids_are_stable_and_ordered() -> None:
    findings = [make_finding(severity=Severity.HIGH), make_finding(severity=Severity.LOW)]
    ids = assign_report_ids(findings, year=2026)
    assert sorted(ids.values()) == ["CK-2026-001", "CK-2026-002"]
    again = assign_report_ids(findings[::-1], year=2026, previous=ids)
    assert again == ids
    scheme = ReportIdScheme(prefix="ACME", width=4, round_component="R2")
    assert scheme.format(7, 2026) == "ACME-2026-R2-0007"


def test_the_document_has_every_audit_section() -> None:
    doc = _doc()
    assert doc.control is not None and doc.scope is not None
    assert [v.report_id for v in doc.views] == ["CK-2026-001", "CK-2026-002"]
    assert doc.executive and doc.roadmap and doc.limitations and doc.methodology.steps
    view = doc.views[0]
    assert view.description and view.impact and view.remediation_short_term
    assert view.compliance and view.references


def test_secrets_never_reach_any_format(tmp_path: Path) -> None:
    doc = _doc(_secret_finding())
    lines = [line.text for e in doc.views[0].evidence for line in e.lines]
    assert not any(AWS_EXAMPLE in line or "hunter2-secret" in line for line in lines)
    registry = renderer_registry()
    for fmt in FORMATS:
        renderer = registry.get(fmt)
        out = renderer.render(doc, tmp_path / f"r.{fmt}.{renderer.extension}")
        data = out.read_bytes()
        if out.suffix in {".xlsx", ".docx"}:
            with zipfile.ZipFile(out) as archive:
                data = b"".join(archive.read(name) for name in archive.namelist())
        assert AWS_EXAMPLE.encode() not in data, fmt
        assert b"hunter2-secret" not in data, fmt


def test_masking_keeps_a_prefix_and_counts() -> None:
    masked, count = mask_lines([f"key = '{AWS_EXAMPLE}'", "plain = 1"])
    assert count >= 1 and masked[0].startswith("key = 'AK") and masked[1] == "plain = 1"


def test_sarif_validates_against_the_official_schema() -> None:
    sarif = build_sarif(_doc())
    jsonschema.Draft4Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(sarif)
    result = sarif["runs"][0]["results"][0]
    assert result["partialFingerprints"]["codekavachFingerprint/v1"].startswith("ckfp1:")
    assert float(result["properties"]["security-severity"]) > 0


def test_csv_neutralises_formulas(tmp_path: Path) -> None:
    assert safe_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and safe_cell("ok") == "ok"
    doc = _doc(make_finding(title="=cmd|' /C calc'!A0"))
    out = renderer_registry().get("csv").render(doc, tmp_path / "r.csv")
    with out.open(encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[1][2].startswith("'=")


def test_markdown_neutralises_mentions_and_html() -> None:
    text = build_markdown(_doc(make_finding(title="ping @octocat <b>x</b> | y")))
    assert "@octocat" not in text and "<b>" not in text and "\\|" in text


def test_sarif_help_markdown_has_no_links_images_or_mentions() -> None:
    hostile = "[Download hotfix](https://evil.example/fix.sh) ![b](https://evil.example/p) @org"
    sarif = build_sarif(_doc(make_finding(remediation=hostile)))
    help_md = sarif["runs"][0]["tool"]["driver"]["rules"][0]["help"]["markdown"]
    assert "\\[Download hotfix\\](https://evil" in help_md
    assert "\\!\\[b\\]" in help_md and "@org" not in help_md
    assert not re.search(r"(?<!\\)[\[\]!]", help_md)


def test_html_has_charts_filters_and_no_remote_fetch() -> None:
    page = render_html(_doc())
    assert page.count("<svg") >= 4 and 'id="ck-q"' in page
    assert "Privacy attestation" in page and "CK-2026-001" in page
    assert "https://" not in page.split("<main>")[0].replace("http://www.w3.org", "")


def test_delta_sorts_new_fixed_and_regressed(tmp_path: Path) -> None:
    kept = make_finding(severity=Severity.LOW, title="Kept")
    gone = make_finding(title="Gone")
    raised = kept.evolve(severity=Severity.HIGH)
    added = make_finding(title="Added")
    delta = build_delta(_doc(raised, added), _doc(kept, gone))
    assert delta.counts == {"new": 1, "fixed": 1, "regressed": 1, "unchanged": 0}
    out = render_delta_html(delta, _doc(raised, added), tmp_path / "delta.html")
    assert "Retest delta report" in out.read_text(encoding="utf-8")


def test_manifest_detects_a_changed_file(tmp_path: Path) -> None:
    (tmp_path / "a.html").write_text("a", encoding="utf-8")
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    manifest, sums = write_manifest(
        [tmp_path / "a.html", tmp_path / "b.json"], tmp_path, doc=_doc()
    )
    assert json.loads(manifest.read_text(encoding="utf-8"))["files"][0]["file"] == "a.html"
    assert "a.html" in sums.read_text(encoding="utf-8")
    assert verify_manifest(tmp_path) == []
    (tmp_path / "a.html").write_text("tampered", encoding="utf-8")
    assert verify_manifest(tmp_path) == ["a.html"]


@pytest.mark.parametrize("fmt", ["xlsx", "docx"])
def test_office_formats_are_valid_archives(tmp_path: Path, fmt: str) -> None:
    out = renderer_registry().get(fmt).render(_doc(), tmp_path / f"r.{fmt}")
    with zipfile.ZipFile(out) as archive:
        assert archive.testzip() is None


def test_xlsx_writes_cvss_scores_as_numbers(tmp_path: Path) -> None:
    doc = _doc(make_finding(severity=Severity.CRITICAL, title="SQL built from input", cwe=(89,)))
    out = renderer_registry().get("xlsx").render(doc, tmp_path / "r.xlsx")
    with zipfile.ZipFile(out) as archive:
        sheet = archive.read("xl/worksheets/sheet2.xml").decode()
    cell = re.search(r'<c r="I2"([^>]*)>(.*?)</c>', sheet)
    assert cell is not None
    assert 't="s"' not in cell.group(1)
    value = re.search(r"<v>(.*?)</v>", cell.group(2))
    assert value is not None
    assert float(value.group(1)) == pytest.approx(9.3)
