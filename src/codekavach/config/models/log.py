"""The ``[logging]`` section, mapped onto ``configure_logging`` (E01-20).

Owning epic: E03. The CLI flags ``--log-level`` and ``--log-format`` (E05-06) override it.
"""

from typing import Literal

from pydantic import Field

from codekavach.config.models.base import SectionModel


class LoggingSettings(SectionModel):
    """Diagnostic logging on stderr."""

    level: Literal["debug", "info", "warning", "error"] = Field(
        default="info", description="Lowest level of events that are written."
    )
    format: Literal["console", "json"] = Field(
        default="console", description="Human-readable console text or one JSON object per line."
    )
