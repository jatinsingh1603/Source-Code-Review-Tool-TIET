"""The renderer protocol and the registry that finds renderers by format name.

Owning epic: E13. MVP; extended by E31, which adds DOCX, SARIF, JSON, CSV, XLSX and Markdown.

A renderer receives a finished ``ReportDocument`` and never a ``CodeSlice``, a ``SanitisedPayload``
or a vault value, so no renderer can send or write anything that the document does not already
hold. Renderers are registered in the ``codekavach.renderers`` entry-point group; a further format
arrives as a registration, not as an edit to the report stage.
"""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable

from codekavach.config import Settings
from codekavach.core.plugins.registry import registry_from_environment
from codekavach.report.model.document import ReportDocument


@runtime_checkable
class Renderer(Protocol):
    """One output format."""

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
