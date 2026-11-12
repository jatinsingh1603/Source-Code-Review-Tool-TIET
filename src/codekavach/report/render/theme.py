"""The white-label theme: colours, fonts and branding shared by every format.

Owning epic: E31 (E31-01). A consultancy changes the theme, not the templates. Colours are
validated as hex so a theme value can never inject CSS.
"""

from typing import ClassVar

from pydantic import Field, field_validator

from codekavach.core.models.base import DataClassification, KavachModel

_HEX = r"^#[0-9a-fA-F]{6}$"


class Theme(KavachModel):
    """Colours and typography of a report."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    name: str = "codekavach"
    brand: str = Field(default="#0b3d91", pattern=_HEX)
    brand_dark: str = Field(default="#072a66", pattern=_HEX)
    accent: str = Field(default="#00897b", pattern=_HEX)
    ink: str = Field(default="#1b2330", pattern=_HEX)
    muted: str = Field(default="#5b6575", pattern=_HEX)
    rule: str = Field(default="#dde3ec", pattern=_HEX)
    surface: str = Field(default="#ffffff", pattern=_HEX)
    panel: str = Field(default="#f5f7fb", pattern=_HEX)
    critical: str = Field(default="#6a1b9a", pattern=_HEX)
    high: str = Field(default="#c62828", pattern=_HEX)
    medium: str = Field(default="#e65100", pattern=_HEX)
    low: str = Field(default="#b58900", pattern=_HEX)
    info: str = Field(default="#1565c0", pattern=_HEX)
    font_body: str = (
        '"Inter", "Segoe UI", "Helvetica Neue", Helvetica, Arial, "Liberation Sans", sans-serif'
    )
    font_mono: str = (
        '"JetBrains Mono", "SFMono-Regular", Menlo, Consolas, "DejaVu Sans Mono", monospace'
    )

    @field_validator("font_body", "font_mono")
    @classmethod
    def _safe_font(cls, value: str) -> str:
        if any(char in value for char in ";{}<>\\"):
            raise ValueError("a font stack must not contain CSS syntax characters")
        return value

    def severity(self, name: str) -> str:
        """The colour of severity ``name``."""
        return str(getattr(self, name, self.muted)) if name in _SEVERITIES else self.muted


_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
DEFAULT_THEME = Theme()
