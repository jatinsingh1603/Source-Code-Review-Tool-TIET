"""The XLSX tracker: formatted sheets a GRC team can work in.

Owning epic: E31 (E31-03).

Sheets: Summary (KPIs, severity table and a native chart), Findings (one row per finding with a
frozen header, filters, severity fills, and Owner, Due date and Status columns with validation),
Roadmap, Compliance and Privacy. XlsxWriter is told never to turn a string into a formula or a
URL, and every cell value passes through the same formula guard as the CSV export.
"""

from datetime import timedelta
from pathlib import Path
from typing import Any, Final

from codekavach.report.model.document import ReportDocument
from codekavach.report.render.exports import CSV_COLUMNS, finding_row, safe_cell
from codekavach.report.render.html import compliance_rows, disclosure_label
from codekavach.report.render.theme import DEFAULT_THEME, Theme

_DUE_DAYS: Final = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
_STATUSES: Final = ["open", "confirmed", "false_positive", "accepted_risk", "suppressed", "fixed"]
# Findings sheet headings; any other column is its CSV name in sentence case.
_HEADINGS: Final = {
    "report_id": "Report ID",
    "cwe": "CWE",
    "owasp": "OWASP",
    "asvs": "ASVS",
    "cvss4_score": "CVSS 4.0 score",
    "cvss4_vector": "CVSS 4.0 vector",
    "cvss31_score": "CVSS 3.1 score",
    "cvss31_vector": "CVSS 3.1 vector",
    "model_verdict": "Model verdict",
}


class XlsxUnavailableError(RuntimeError):
    """XlsxWriter is not installed."""

    reason_code = "missing_optional_extra"


class XlsxRenderer:
    """Writes the report as an Excel workbook."""

    format = "xlsx"
    extension = "xlsx"
    binary = True

    def render(  # noqa: PLR0912, PLR0915 - one workbook, written sheet by sheet
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``."""
        try:
            import xlsxwriter  # type: ignore[import-untyped]  # noqa: PLC0415 - optional extra
        except ImportError as error:
            raise XlsxUnavailableError("install the reports extra for XLSX output") from error
        t = theme or DEFAULT_THEME
        out.parent.mkdir(parents=True, exist_ok=True)
        book = xlsxwriter.Workbook(
            str(out),
            {
                "strings_to_formulas": False,
                "strings_to_urls": False,
                "strings_to_numbers": False,
            },
        )
        book.set_properties(
            {
                "title": f"{doc.title}: {doc.project_name}",
                "subject": doc.report_id,
                "author": doc.organisation,
                "company": doc.organisation,
                "comments": f"Classification: {doc.classification}",
                "created": doc.generated_at.replace(tzinfo=None),
            }
        )
        title = book.add_format({"bold": True, "font_size": 18, "font_color": t.brand})
        sub = book.add_format({"font_color": t.muted, "italic": True})
        head = book.add_format(
            {
                "bold": True,
                "font_color": "#FFFFFF",
                "bg_color": t.brand_dark,
                "border": 1,
                "text_wrap": True,
                "valign": "top",
            }
        )
        cell = book.add_format({"text_wrap": True, "valign": "top", "border": 1})
        mono = book.add_format(
            {"font_name": "Consolas", "font_size": 9, "valign": "top", "border": 1}
        )
        date = book.add_format({"num_format": "yyyy-mm-dd", "valign": "top", "border": 1})
        sev_fmt = {
            name: book.add_format(
                {
                    "bold": True,
                    "font_color": "#FFFFFF",
                    "bg_color": t.severity(name),
                    "align": "center",
                    "valign": "top",
                    "border": 1,
                }
            )
            for name in ("critical", "high", "medium", "low", "info")
        }
        kpi = book.add_format({"bold": True, "font_size": 20, "align": "center"})
        kpi_label = book.add_format({"font_color": t.muted, "align": "center"})

        # Summary
        ws = book.add_worksheet("Summary")
        ws.hide_gridlines(2)
        ws.set_column(0, 0, 26)
        ws.set_column(1, 6, 16)
        ws.write(0, 0, safe_cell(f"{doc.title}: {doc.project_name}"), title)
        ws.write(1, 0, safe_cell(f"{doc.report_id} · {doc.classification}"), sub)
        rows = [
            ("Prepared for", doc.prepared_for),
            ("Prepared by", doc.organisation),
            ("Scan", str(doc.scan.id)),
            ("Generated", doc.generated_at.strftime("%Y-%m-%d %H:%M UTC")),
            ("Overall risk", doc.facts.posture if doc.facts else "n/a"),
            ("Privacy level", str(doc.scan.privacy_level.value)),
            ("Provider / model", f"{doc.scan.provider or 'none'} / {doc.scan.model or 'none'}"),
        ]
        for index, (key, value) in enumerate(rows, start=3):
            ws.write(index, 0, key, book.add_format({"bold": True}))
            ws.write(index, 1, safe_cell(value))
        counts = list(doc.facts.by_severity) if doc.facts else []
        base = 3 + len(rows) + 1
        for col, (name, count) in enumerate(counts, start=1):
            ws.write(base, col, count, kpi)
            ws.write(base + 1, col, name.title(), kpi_label)
        table = base + 3
        ws.write(table, 0, "Severity", head)
        ws.write(table, 1, "Findings", head)
        for index, (name, count) in enumerate(counts, start=1):
            ws.write(table + index, 0, name.title(), sev_fmt[name])
            ws.write(table + index, 1, count, cell)
        if counts:
            chart = book.add_chart({"type": "bar"})
            chart.add_series(
                {
                    "name": "Findings",
                    "categories": ["Summary", table + 1, 0, table + len(counts), 0],
                    "values": ["Summary", table + 1, 1, table + len(counts), 1],
                    "points": [{"fill": {"color": t.severity(name)}} for name, _ in counts],
                    "data_labels": {"value": True},
                }
            )
            chart.set_title({"name": "Findings by severity"})
            chart.set_legend({"none": True})
            chart.set_y_axis({"reverse": True})
            ws.insert_chart(table, 3, chart, {"x_scale": 1.1, "y_scale": 0.9})

        # Findings
        wf = book.add_worksheet("Findings")
        columns = [*CSV_COLUMNS, "owner", "due_date", "tracker_status", "comment"]
        widths = {
            "title": 48,
            "remediation": 60,
            "compliance": 40,
            "file": 34,
            "fingerprint": 30,
            "cvss4_vector": 30,
            "cvss31_vector": 30,
            "owner": 18,
            "due_date": 12,
            "comment": 30,
        }
        for col, name in enumerate(columns):
            wf.write(0, col, _HEADINGS.get(name, name.replace("_", " ").capitalize()), head)
            wf.set_column(col, col, widths.get(name, 13))
        wf.freeze_panes(1, 2)
        wf.set_row(0, 30)
        due_base = doc.generated_at.replace(tzinfo=None)
        for row, view in enumerate(doc.views, start=1):
            values = finding_row(view)
            for col, value in enumerate(values):
                name = CSV_COLUMNS[col]
                if name == "severity":
                    wf.write_string(row, col, value, sev_fmt.get(view.severity, cell))
                elif name in {"fingerprint", "cvss4_vector", "cvss31_vector", "file"}:
                    wf.write_string(row, col, value, mono)
                elif name in {"line", "likelihood", "impact", "risk_score"} and value.isdigit():
                    wf.write_number(row, col, int(value), cell)
                else:
                    wf.write_string(row, col, value, cell)
            extra = len(CSV_COLUMNS)
            wf.write_string(row, extra, "", cell)
            wf.write_datetime(
                row,
                extra + 1,
                due_base + timedelta(days=_DUE_DAYS.get(view.severity, 90)),
                date,
            )
            wf.write_string(row, extra + 2, view.status, cell)
            wf.write_string(row, extra + 3, "", cell)
        last = max(len(doc.views), 1)
        wf.autofilter(0, 0, last, len(columns) - 1)
        wf.data_validation(
            1,
            len(CSV_COLUMNS) + 2,
            max(last, 200),
            len(CSV_COLUMNS) + 2,
            {"validate": "list", "source": _STATUSES},
        )

        # Roadmap
        wr = book.add_worksheet("Roadmap")
        for col, (name, width) in enumerate(
            (("Priority", 10), ("Lane", 14), ("Window", 16), ("Weakness", 32), ("Action", 70),
             ("Effort", 10), ("Findings", 40))
        ):  # fmt: skip
            wr.write(0, col, name, head)
            wr.set_column(col, col, width)
        wr.freeze_panes(1, 0)
        for row, item in enumerate(doc.roadmap, start=1):
            for col, value in enumerate(
                (item.priority, item.lane, item.window, item.theme, item.action, item.effort,
                 ", ".join(item.report_ids))
            ):  # fmt: skip
                wr.write_string(row, col, safe_cell(value), cell)

        # Compliance
        wc = book.add_worksheet("Compliance")
        for col, (name, width) in enumerate(
            (("Framework", 24), ("Control", 16), ("Title", 44), ("Findings", 60))
        ):
            wc.write(0, col, name, head)
            wc.set_column(col, col, width)
        wc.freeze_panes(1, 0)
        for row, annex in enumerate(compliance_rows(doc), start=1):
            wc.write_string(row, 0, safe_cell(annex.framework), cell)
            wc.write_string(row, 1, safe_cell(annex.clause), cell)
            wc.write_string(row, 2, safe_cell(annex.title or ""), cell)
            wc.write_string(row, 3, safe_cell(", ".join(annex.ids)), cell)

        # Privacy
        att = doc.privacy_attestation
        if att is not None:
            wp = book.add_worksheet("Privacy")
            wp.set_column(0, 0, 32)
            wp.set_column(1, 1, 80)
            wp.write(0, 0, "Privacy attestation", title)
            facts = [
                ("Privacy level", att.default_level),
                ("Provider / model", f"{att.provider or 'none'} / {att.model or 'none'}"),
                ("Ledger entries", str(att.ledger_entries)),
                ("Payloads sent / blocked", f"{att.requests_sent} / {att.requests_blocked}"),
                ("Tokens (prompt)", str(att.tokens_prompt)),
                ("Ledger head hash", att.ledger_head_hash or "none"),
                ("Chain verification", att.chain_text),
                ("Zero-leak check", att.zero_leak.text),
                (
                    "Placeholders",
                    ", ".join(f"{k}: {v}" for k, v in att.placeholders_by_type) or "none",
                ),
                *((disclosure_label(name), value) for name, value in att.disclosure),
                ("Not covered", att.not_covered),
            ]
            for row, (key, value) in enumerate(facts, start=2):
                wp.write_string(row, 0, key, head)
                wp.write_string(row, 1, safe_cell(value), cell)
        book.close()
        return out
