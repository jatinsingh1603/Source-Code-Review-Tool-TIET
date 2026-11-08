"""The PDF report, produced from the HTML template through its print styles.

Owning epic: E13. MVP; extended by E31, which adds the cover page layouts and bookmarks.

WeasyPrint is an optional dependency (the ``reports`` extra) and needs the Pango system libraries.
When either is missing the renderer raises ``PdfUnavailableError`` and the report command lists the
format as not written; the HTML report is the same document and stays available. The fetcher given
to WeasyPrint refuses every URL, so rendering can never make a network request or read a file.
"""

from pathlib import Path
from typing import Any

from codekavach.report.model.document import ReportDocument
from codekavach.report.render.html import render_html


class PdfUnavailableError(RuntimeError):
    """The PDF engine or its system libraries are not installed."""


def _refuse(url: str, *args: Any, **kwargs: Any) -> Any:
    raise ValueError("the report references no external resource")


class PdfRenderer:
    """Writes the report as a PDF with page numbers, a running header and a contents list."""

    format = "pdf"
    extension = "pdf"

    def render(self, doc: ReportDocument, out: Path) -> Path:
        """Write ``doc`` to ``out``.

        Raises:
            PdfUnavailableError: WeasyPrint or its system libraries cannot be loaded.
        """
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]  # noqa: PLC0415 - optional
        except (ImportError, OSError) as error:
            raise PdfUnavailableError("the PDF engine is not available") from error
        out.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=render_html(doc), url_fetcher=_refuse).write_pdf(str(out))
        return out
