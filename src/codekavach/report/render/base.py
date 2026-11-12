"""The renderer protocol and the registry that finds renderers by format name.

Owning epic: E13. MVP; extended by E31, which adds DOCX, SARIF, JSON, CSV, XLSX and Markdown.

A renderer receives a finished ``ReportDocument`` and never a ``CodeSlice``, a ``SanitisedPayload``
or a vault value, so no renderer can send or write anything that the document does not already
hold. Renderers are registered in the ``codekavach.renderers`` entry-point group; a further format
arrives as a registration, not as an edit to the report stage.
"""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

from codekavach.config import Settings
from codekavach.core.plugins.registry import registry_from_environment
from codekavach.report.model.document import ReportDocument

REASON_CODES: Final = frozenset(
    {
        "missing_system_library",
        "missing_optional_extra",
        "template_error",
        "asset_not_found",
        "output_too_large",
        "unsupported_language",
    }
)


class RenderError(Exception):
    """A renderer could not write its format; ``reason_code`` is one of ``REASON_CODES``."""

    def __init__(self, message: str, *, reason_code: str = "template_error") -> None:
        super().__init__(message)
        self.reason_code = reason_code if reason_code in REASON_CODES else "template_error"


@runtime_checkable
class Renderer(Protocol):
    """One output format.

    Built-in renderers also set ``binary: bool`` and accept keyword-only ``theme`` and
    ``context`` arguments with defaults, so the call ``renderer.render(doc, out)`` always works.
    """

    format: str
    extension: str

    def render(self, doc: ReportDocument, out: Path) -> Path:
        """Write ``doc`` to the file ``out`` and return the path written."""


class RendererRegistry:
    """The installed renderers by format name."""

    def __init__(self, renderers: Mapping[str, Renderer]) -> None:
        self._renderers = dict(sorted(renderers.items()))

    def names(self) -> Sequence[str]:
        """The format names that can be rendered, sorted."""
        return tuple(self._renderers)

    def get(self, name: str) -> Renderer:
        """The renderer of format ``name``.

        Raises:
            KeyError: no renderer provides it.
        """
        return self._renderers[name]


def renderer_registry(settings: Settings | None = None) -> RendererRegistry:
    """The renderers installed in this environment, built-in and plugin, filtered by policy."""
    found = registry_from_environment(settings).renderers()
    return RendererRegistry(
        {name: item for name, item in found.items() if isinstance(item, Renderer)}
    )
