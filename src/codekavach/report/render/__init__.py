"""Renderers: HTML, PDF, DOCX, SARIF, JSON, CSV, XLSX and Markdown.

Owning epic: E31. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.report.render.base import Renderer, RendererRegistry, renderer_registry

__all__ = ["Renderer", "RendererRegistry", "renderer_registry"]
