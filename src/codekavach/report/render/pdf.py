"""The PDF report, produced from the HTML template through its paged-media styles.

Owning epic: E13. MVP; extended by E31 (E31-02): full-bleed cover, linked table of contents with
page numbers, running header with the classification, footer with the report id and page x of y,
and PDF bookmarks from the headings.

WeasyPrint is an optional dependency (the ``reports`` extra) and needs the Pango system libraries.
When either is missing the renderer raises ``PdfUnavailableError`` and the report command lists the
format as not written; the HTML report is the same document and stays available. The fetcher given
to WeasyPrint refuses every URL, so rendering can never make a network request or read a file.
"""

from pathlib import Path
from typing import Any

from codekavach.report.model.document import ReportDocument
from codekavach.report.render.html import render_html
from codekavach.report.render.theme import Theme


class PdfUnavailableError(RuntimeError):
    """The PDF engine or its system libraries are not installed."""

    reason_code = "missing_system_library"


def _refuse(url: str, *args: Any, **kwargs: Any) -> Any:
    raise ValueError("the report references no external resource")


def check_prerequisites() -> tuple[str, ...]:
    """What is missing for the PDF renderer, empty when it can render."""
    try:
        import weasyprint  # type: ignore[import-untyped]  # noqa: F401, PLC0415 - optional
    except (ImportError, OSError):
        return ("weasyprint (pip install 'codekavach[reports]') and the Pango libraries",)
    return ()


class PdfRenderer:
    """Writes the report as a paginated A4 PDF."""

    format = "pdf"
    extension = "pdf"
    binary = True

    def render(
        self, doc: ReportDocument, out: Path, *, theme: Theme | None = None, context: Any = None
    ) -> Path:
        """Write ``doc`` to ``out``.

        Raises:
            PdfUnavailableError: WeasyPrint or its system libraries cannot be loaded.
        """
        try:
            from weasyprint import HTML  # noqa: PLC0415 - optional
        except (ImportError, OSError) as error:
            raise PdfUnavailableError("the PDF engine is not available") from error
        out.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=render_html(doc, pdf=True, theme=theme), url_fetcher=_refuse).write_pdf(
            str(out)
        )
        return out
