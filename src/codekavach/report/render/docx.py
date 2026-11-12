"""The Word report, built programmatically with python-docx.

Owning epic: E31 (E31-04).

The document carries the same sections as the HTML and PDF: cover, document control, a table of
contents field, executive summary, scope, methodology, rating method, findings summary, detailed
findings with highlighted, line-numbered evidence, roadmap, privacy attestation and appendices.
Headers carry the classification, footers the report id and a page-number field. Word fills the
table of contents when the document is opened and fields are updated (F9); the placeholder says
so rather than pretending the page numbers are already there. A client Word template (docxtpl) is
not supported yet.
"""

from pathlib import Path
from typing import Any, Final

from codekavach.report.model.document import ReportDocument
from codekavach.report.model.finding_view import FindingView
from codekavach.report.render.html import compliance_rows
from codekavach.report.render.snippets import token_rows
from codekavach.report.render.theme import DEFAULT_THEME, Theme

MONO: Final = "Consolas"


class DocxUnavailableError(RuntimeError):
    """python-docx is not installed."""

    reason_code = "missing_optional_extra"


def _hex(value: str) -> str:
    return value.lstrip("#").upper()


class _Builder:
    """Small helpers over one python-docx document."""

    def __init__(self, theme: Theme) -> None:
        import docx  # noqa: PLC0415 - optional extra
        from docx.enum.text import WD_ALIGN_PARAGRAPH  # noqa: PLC0415
        from docx.oxml import OxmlElement  # noqa: PLC0415
        from docx.oxml.ns import qn  # noqa: PLC0415
        from docx.shared import Mm, Pt, RGBColor  # noqa: PLC0415

        self.docx, self.align, self.Oxml, self.qn = docx, WD_ALIGN_PARAGRAPH, OxmlElement, qn
        self.Pt, self.Mm, self.RGB = Pt, Mm, RGBColor
        self.theme = theme
        self.doc = docx.Document()
        section = self.doc.sections[0]
        section.page_height, section.page_width = Mm(297), Mm(210)
        section.left_margin = section.right_margin = Mm(18)
        section.top_margin, section.bottom_margin = Mm(20), Mm(18)
        styles = self.doc.styles
        normal = styles["Normal"]
        normal.font.name = "Calibri"
        normal.font.size = Pt(10)
        for level, size in ((1, 18), (2, 14), (3, 12)):
            style = styles[f"Heading {level}"]
            style.font.name = "Calibri"
            style.font.size = Pt(size)
            style.font.color.rgb = RGBColor.from_string(_hex(theme.brand))

    def rgb(self, value: str) -> Any:
        return self.RGB.from_string(_hex(value))

    def shade(self, cell: Any, colour: str) -> None:
        props = cell._tc.get_or_add_tcPr()
        shd = self.Oxml("w:shd")
        shd.set(self.qn("w:val"), "clear")
        shd.set(self.qn("w:color"), "auto")
        shd.set(self.qn("w:fill"), _hex(colour))
        props.append(shd)

    def field(self, paragraph: Any, instruction: str, placeholder: str = "") -> None:
        run = paragraph.add_run()
        begin = self.Oxml("w:fldChar")
        begin.set(self.qn("w:fldCharType"), "begin")
        run._r.append(begin)
        instr = self.Oxml("w:instrText")
        instr.set(self.qn("xml:space"), "preserve")
        instr.text = instruction
        run._r.append(instr)
        sep = self.Oxml("w:fldChar")
        sep.set(self.qn("w:fldCharType"), "separate")
        run._r.append(sep)
        paragraph.add_run(placeholder)
        end_run = paragraph.add_run()
        end = self.Oxml("w:fldChar")
        end.set(self.qn("w:fldCharType"), "end")
        end_run._r.append(end)

    def para(
        self,
        text: str = "",
        *,
        bold: bool = False,
        size: float | None = None,
        colour: str | None = None,
        italic: bool = False,
        style: str | None = None,
    ) -> Any:
        paragraph = self.doc.add_paragraph(style=style)
        if text:
            run = paragraph.add_run(text)
            run.bold, run.italic = bold, italic
            if size:
                run.font.size = self.Pt(size)
            if colour:
                run.font.color.rgb = self.rgb(colour)
        return paragraph

    def table(
        self, header: list[str], rows: list[list[str]], widths: list[float] | None = None
    ) -> Any:
        table = self.doc.add_table(rows=1, cols=len(header))
        table.style = "Table Grid"
        for index, name in enumerate(header):
            cell = table.rows[0].cells[index]
            cell.text = ""
            run = cell.paragraphs[0].add_run(name)
            run.bold = True
            run.font.size = self.Pt(8.5)
            run.font.color.rgb = self.rgb("#ffffff")
            self.shade(cell, self.theme.brand_dark)
        for values in rows:
            cells = table.add_row().cells
            for index, value in enumerate(values):
                cells[index].text = ""
                run = cells[index].paragraphs[0].add_run(str(value))
                run.font.size = self.Pt(8.5)
        if widths:
            for row in table.rows:
                for index, width in enumerate(widths):
                    row.cells[index].width = self.Mm(width)
        return table

    def kv(self, rows: list[tuple[str, str]]) -> Any:
        table = self.doc.add_table(rows=0, cols=2)
        table.style = "Table Grid"
        for key, value in rows:
            cells = table.add_row().cells
            cells[0].text = ""
            run = cells[0].paragraphs[0].add_run(key)
            run.bold = True
            run.font.size = self.Pt(9)
            self.shade(cells[0], self.theme.panel)
            cells[1].text = ""
            cells[1].paragraphs[0].add_run(str(value)).font.size = self.Pt(9)
            cells[0].width, cells[1].width = self.Mm(50), self.Mm(124)
        return table

    def severity_cell(self, cell: Any, severity: str) -> None:
        cell.text = ""
        run = cell.paragraphs[0].add_run(severity.upper())
        run.bold = True
        run.font.size = self.Pt(8)
        run.font.color.rgb = self.rgb("#ffffff")
        self.shade(cell, self.theme.severity(severity))


def _cover(b: _Builder, doc: ReportDocument) -> None:
    b.para()
    b.para(doc.classification.upper(), bold=True, size=9, colour=b.theme.critical)
    for _ in range(4):
        b.para()
    b.para("SECURITY ASSESSMENT REPORT", bold=True, size=10, colour=b.theme.muted)
    b.para(doc.title, bold=True, size=28, colour=b.theme.brand_dark)
    b.para(doc.project_name, size=18, colour=b.theme.brand)
    b.para()
    b.kv(
        [
            ("Prepared for", doc.prepared_for),
            ("Prepared by", doc.organisation),
            ("Report ID", doc.report_id),
            ("Version", doc.version),
            ("Issue date", doc.control.issue_date if doc.control else ""),
            ("Overall risk", doc.facts.posture if doc.facts else "n/a"),
        ]
    )
    b.doc.add_page_break()  # type: ignore[no-untyped-call]


def _finding(b: _Builder, v: FindingView) -> None:
    heading = b.doc.add_heading(level=3)
    heading.add_run(f"{v.report_id}  ").font.color.rgb = b.rgb(b.theme.muted)
    heading.add_run(v.title)
    facts = b.doc.add_table(rows=1, cols=4)
    facts.style = "Table Grid"
    b.severity_cell(facts.rows[0].cells[0], v.severity)
    values = [
        f"Risk {v.likelihood} x {v.impact_level} = {v.risk_score} ({v.risk_band})",
        f"Confidence {v.confidence} · {v.status.replace('_', ' ')}",
        f"{v.priority} · {v.lane}",
    ]
    for index, value in enumerate(values, start=1):
        cell = facts.rows[0].cells[index]
        cell.text = ""
        cell.paragraphs[0].add_run(value).font.size = b.Pt(8.5)
    b.kv(
        [
            ("CWE", "; ".join(f"CWE-{c} {n}" for c, n in zip(v.cwe, v.cwe_names, strict=False))
             or "n/a"),
            ("OWASP Top 10", v.owasp_label),
            ("ASVS / CAPEC", f"{', '.join(v.asvs) or 'n/a'} / {', '.join(v.capec) or 'n/a'}"),
            ("CVSS v4.0", f"{v.rating.cvss4_score} {v.rating.cvss4_vector}"
             if v.rating.cvss4_vector else "Not scored"),
            ("CVSS v3.1", f"{v.rating.cvss31_score or ''} {v.rating.cvss31_vector}".strip()
             if v.rating.cvss31_vector else "Not scored"),
            ("Location", ", ".join(v.locations) + (f" in {v.symbol}" if v.symbol else "")),
            ("Detected by", ", ".join(v.detected_by) or v.origin),
        ]
    )  # fmt: skip
    b.para("Description", bold=True, colour=b.theme.brand)
    b.para(v.description)
    for evidence in v.evidence:
        b.para(
            f"Evidence: {evidence.path}, line {evidence.start_line}"
            + (" (secrets masked)" if evidence.masked_values else ""),
            bold=True,
            colour=b.theme.brand,
        )
        rows = token_rows(evidence)
        table = b.doc.add_table(rows=0, cols=2)
        table.style = "Table Grid"
        for row in rows:
            cells = table.add_row().cells
            cells[0].width, cells[1].width = b.Mm(12), b.Mm(162)
            number = cells[0].paragraphs[0].add_run(str(row.number))
            number.font.name, number.font.size = MONO, b.Pt(7.5)
            number.font.color.rgb = b.rgb(b.theme.muted)
            paragraph = cells[1].paragraphs[0]
            for run in row.runs:
                r = paragraph.add_run(run.text)
                r.font.name, r.font.size = MONO, b.Pt(7.5)
                r.bold, r.italic = run.bold, run.italic
                if run.colour:
                    r.font.color.rgb = b.rgb(run.colour)
            fill = "#fff4cc" if row.marked else "#f7f8fb"
            b.shade(cells[0], fill)
            b.shade(cells[1], fill)
    if v.flow:
        b.para("Data flow", bold=True, colour=b.theme.brand)
        b.table(
            ["#", "Role", "Location", "Note"],
            [
                [str(s.index), s.role, f"{s.path}:{s.line}", s.note or s.symbol or ""]
                for s in v.flow
            ],
            [10, 24, 70, 70],
        )
    if v.verdict:
        b.para(
            f"Model assessment: {v.verdict.label} ({v.verdict.confidence} confidence), "
            f"{v.verdict.provider} / {v.verdict.model}",
            bold=True,
            colour=b.theme.accent,
        )
        if v.verdict.reasoning:
            b.para(v.verdict.reasoning, italic=True)
    b.para("Impact", bold=True, colour=b.theme.brand)
    b.para(v.impact)
    b.para("Remediation", bold=True, colour=b.theme.brand)
    b.para(f"Fix now: {v.remediation_short_term}")
    b.para(f"Prevent recurrence: {v.remediation_long_term}")
    if v.compliance:
        b.para(
            "Compliance: " + "; ".join(f"{c.framework} {c.clause}" for c in v.compliance),
            size=8.5,
            colour=b.theme.muted,
        )
    if v.references:
        b.para(
            "References: " + "; ".join(f"{t} ({u})" if u else t for t, u in v.references),
            size=8,
            colour=b.theme.muted,
        )


def build_docx(doc: ReportDocument, out: Path, theme: Theme) -> None:  # noqa: PLR0912, PLR0915
    """Write the Word document for ``doc`` to ``out``."""
    b = _Builder(theme)
    section = b.doc.sections[0]
    header = section.header.paragraphs[0]
    header.text = f"{doc.classification.upper()}    {doc.report_id}"
    header.runs[0].font.size = b.Pt(8)
    header.runs[0].font.color.rgb = b.rgb(theme.critical)
    footer = section.footer.paragraphs[0]
    footer.add_run(f"{doc.report_id} · {doc.project_name} · Page ").font.size = b.Pt(8)
    b.field(footer, "PAGE", "1")
    _cover(b, doc)
    if doc.control:
        b.doc.add_heading("Document control", level=1)
        c = doc.control
        b.kv(
            [
                ("Report identifier", c.report_id),
                ("Version", c.version),
                ("Issue date", c.issue_date),
                ("Classification", f"{c.classification.label}. {c.classification.handling_note}"),
                ("Prepared by", c.prepared_by),
                ("Prepared for", c.prepared_for),
                ("Scan identifier", str(doc.scan.id)),
            ]
        )
        b.para()
        b.table(
            ["Role", "Name", "Signature / date"],
            [[s.role, s.name, ""] for s in c.sign_offs],
            [50, 60, 64],
        )
        b.para(c.disclaimer, size=8, colour=theme.muted)
    b.doc.add_heading("Contents", level=1)
    toc = b.doc.add_paragraph()
    b.field(
        toc,
        'TOC \\o "1-3" \\h \\z \\u',
        "Right-click and choose Update Field (or press F9) to build the table of contents.",
    )
    b.doc.add_page_break()  # type: ignore[no-untyped-call]

    b.doc.add_heading("1 Executive summary", level=1)
    if doc.facts:
        table = b.doc.add_table(rows=2, cols=5)
        table.style = "Table Grid"
        for index, (name, count) in enumerate(doc.facts.by_severity):
            top = table.rows[0].cells[index]
            top.text = ""
            run = top.paragraphs[0].add_run(str(count))
            run.bold, run.font.size = True, b.Pt(18)
            b.severity_cell(table.rows[1].cells[index], name)
        band = doc.facts.posture.lower().replace("moderate", "medium")
        b.para(
            f"Overall risk: {doc.facts.posture}", bold=True, size=13, colour=theme.severity(band)
        )
    for block in doc.executive:
        if block.id != "overview":
            b.doc.add_heading(block.heading, level=2)
        for paragraph in block.paragraphs:
            b.para(paragraph)
        for item in block.bullets:
            b.para(item, style="List Bullet")

    b.doc.add_heading("2 Scope and approach", level=1)
    if doc.scope:
        b.kv(
            [
                ("Client", doc.scope.client_name),
                ("Engagement", f"{doc.scope.engagement_id}: {doc.scope.engagement_type}"),
                ("Period", f"{doc.scope.period_start} to {doc.scope.period_end}"),
                *((("Target", t.repository + (f" @ {t.commit[:12]}" if t.commit else "")))
                  for t in doc.scope.targets),
                ("Files analysed", f"{doc.coverage.files_analysed} files, "
                 f"{doc.coverage.lines_analysed:,} lines"),
            ]
        )  # fmt: skip
        for objective in doc.scope.objectives:
            b.para(objective, style="List Bullet")

    b.doc.add_heading("3 Methodology", level=1)
    b.table(
        ["Phase", "Step", "Description"],
        [[s.phase.value.title(), s.title, s.description] for s in doc.methodology.steps],
        [24, 34, 116],
    )
    b.doc.add_heading("Privacy levels", level=2)
    b.table(
        ["Level", "Name", "What is sent"],
        [[p.level, p.name, p.sends] for p in doc.methodology.privacy_levels],
        [16, 40, 118],
    )

    b.doc.add_heading("4 Risk rating method", level=1)
    b.table(
        ["Severity", "CVSS", "Meaning"],
        [[n.title(), band, m] for n, band, m in doc.rating_method.severity_scale],
        [24, 24, 126],
    )
    b.para(doc.rating_method.cvss_nomenclature, size=8.5)
    b.table(
        ["#", "Likelihood", "Impact"],
        [
            [str(n), lt, it]
            for (n, lt), (_, it) in zip(
                doc.rating_method.likelihood_scale, doc.rating_method.impact_scale, strict=False
            )
        ],
        [10, 82, 82],
    )

    b.doc.add_heading("5 Summary of findings", level=1)
    table = b.table(
        ["ID", "Severity", "Title", "CWE", "Location", "Status"],
        [
            [v.report_id, "", v.title, v.cwe_label, v.location_label, v.status.replace("_", " ")]
            for v in doc.views
        ],
        [24, 18, 60, 18, 40, 14],
    )
    for index, v in enumerate(doc.views, start=1):
        b.severity_cell(table.rows[index].cells[1], v.severity)

    b.doc.add_heading("6 Detailed findings", level=1)
    for v in doc.views:
        _finding(b, v)

    b.doc.add_heading("7 Remediation roadmap", level=1)
    b.table(
        ["Priority", "Timeline", "Weakness", "Action", "Findings"],
        [
            [r.priority, f"{r.lane} ({r.window})", r.theme, r.action, ", ".join(r.report_ids)]
            for r in doc.roadmap
        ],
        [14, 28, 30, 70, 32],
    )

    att = doc.privacy_attestation
    if att:
        b.doc.add_heading("8 Privacy attestation", level=1)
        if att.offline_notice:
            b.para(att.offline_notice, italic=True, colour=theme.high)
        b.kv(
            [
                ("Privacy level", att.default_level),
                ("Provider / model", f"{att.provider or 'none'} / {att.model or 'none'}"),
                ("Ledger entries", str(att.ledger_entries)),
                ("Payloads sent / blocked", f"{att.requests_sent} / {att.requests_blocked}"),
                ("Tokens (prompt / completion)", f"{att.tokens_prompt} / {att.tokens_completion}"),
                ("Placeholders", ", ".join(f"{k}: {n}" for k, n in att.placeholders_by_type)
                 or ("none" if att.placeholders_counted else "not counted")),
                *((k.replace("_", " "), v) for k, v in att.disclosure),
                ("Ledger head hash", att.ledger_head_hash or "none"),
                ("Chain verification", att.chain_text),
                ("Zero-leak check", att.zero_leak.text),
                ("Retention", att.retention),
            ]
        )  # fmt: skip
        b.para(att.not_covered, size=8.5, colour=theme.muted)

    b.doc.add_heading("Appendices", level=1)
    b.doc.add_heading("A. Tools and versions", level=2)
    b.table(
        ["Tool", "Version", "Role"],
        [[t.name, t.version, t.role] for t in doc.methodology.tools],
        [50, 30, 94],
    )
    b.doc.add_heading("B. Compliance annex", level=2)
    b.para(
        "Findings listed against a control are evidence against it, not an opinion of compliance.",
        size=8.5,
        colour=theme.muted,
    )
    b.table(
        ["Framework", "Control", "Title", "Findings"],
        [[r.framework, r.clause, r.title or "", ", ".join(r.ids)] for r in compliance_rows(doc)],
        [34, 22, 50, 68],
    )
    if doc.coverage.files_reviewed:
        b.doc.add_heading("C. Files reviewed", level=2)
        for path in doc.coverage.files_reviewed:
            b.para(path, size=8)
    b.doc.add_heading("Limitations", level=2)
    for limitation in doc.limitations:
        b.para(f"{limitation.id} ({limitation.kind}): {limitation.statement}", style="List Bullet")
    props = b.doc.core_properties
    props.title = f"{doc.title}: {doc.project_name}"
    props.author = doc.organisation
    props.subject = doc.report_id
    props.keywords = doc.classification
    out.parent.mkdir(parents=True, exist_ok=True)
    b.doc.save(str(out))


class DocxRenderer:
    """Writes the report as a Word document."""

    format = "docx"
    extension = "docx"
    binary = True

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``.

        Raises:
            DocxUnavailableError: python-docx is not installed.
        """
        try:
            import docx  # noqa: F401, PLC0415 - optional extra
        except ImportError as error:
            raise DocxUnavailableError("install the reports extra for DOCX output") from error
        build_docx(doc, out, theme or DEFAULT_THEME)
        return out
