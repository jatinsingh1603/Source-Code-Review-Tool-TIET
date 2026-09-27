"""The ``[reporting]`` section: which reports are written, where and how.

Owning epic: E03.

Evidence is text with line numbers (requirement R9); this section has no screenshot, video or
image-evidence switch, and a test keeps it that way. ``template_dir`` is restricted because a
template is code run by the template engine (CWE-1336). Enum values are part of the file format
and change only with a ``config_version`` bump.
"""

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

from pydantic import BeforeValidator, Field, field_validator

from codekavach.config.models.base import (
    INVALID,
    SectionModel,
    bounds,
    in_range,
    restricted,
    split_csv,
    volatile,
)
from codekavach.core.models import Severity

MAX_TEXT_LENGTH = 200
MAX_CLASSIFICATION_LENGTH = 60
LOGO_SUFFIXES = frozenset({".png", ".svg"})


class ReportFormat(StrEnum):
    """Report output formats (requirement R8)."""

    html = "html"
    pdf = "pdf"
    docx = "docx"
    sarif = "sarif"
    json = "json"
    csv = "csv"
    xlsx = "xlsx"
    markdown = "markdown"


class ComplianceFramework(StrEnum):
    """Frameworks a report maps findings to."""

    owasp_top10 = "owasp-top10"
    owasp_asvs = "owasp-asvs"
    cwe_top25 = "cwe-top25"
    capec = "capec"
    pci_dss = "pci-dss"
    iso27001 = "iso27001"
    nist_ssdf = "nist-ssdf"
    rbi = "rbi"
    sebi = "sebi"


def _enum_list(enum: type[StrEnum], key: str) -> BeforeValidator:
    """Split comma-separated input, reject unknown values with CK-CFG-003, drop duplicates."""
    allowed = {member.value for member in enum}

    def check(value: Any) -> Any:
        value = split_csv(value)
        if not isinstance(value, list):
            return value
        result: list[Any] = []
        for item in value:
            text = item.value if isinstance(item, StrEnum) else item
            if not isinstance(text, str) or text.strip().lower() not in allowed:
                raise ValueError(f"{INVALID} {key} entries must be one of {sorted(allowed)}")
            if (normalised := text.strip().lower()) not in result:
                result.append(normalised)
        return result

    return BeforeValidator(check)


def _check_length(key: str, value: str, high: int) -> str:
    if not 1 <= len(value) <= high:
        raise ValueError(f"{INVALID} {key} must be 1 to {high} characters")
    return value


class ReportingSettings(SectionModel):
    """Which reports are written, where, and how much context they show."""

    formats: Annotated[list[ReportFormat], _enum_list(ReportFormat, "reporting.formats")] = Field(
        default_factory=lambda: [ReportFormat.html, ReportFormat.sarif, ReportFormat.json],
        description="Report formats to write.",
    )
    output_dir: Path = Field(
        # A string default keeps the JSON Schema serialisable; validate_default makes it a Path.
        default="codekavach-report",
        description="Directory for reports, relative to the project root.",
        json_schema_extra=volatile(),
    )
    title: str | None = Field(
        default=None,
        description="Report title; defaults to 'Secure Source Code Review: <project name>'.",
    )
    classification: str = Field(
        default="Confidential", description="Classification printed in header and footer."
    )
    auditor: str | None = Field(
        default=None, description="Reviewing person or firm, for document control."
    )
    logo: Path | None = Field(default=None, description="PNG or SVG image for the cover.")
    template_dir: Path | None = Field(
        default=None,
        description="Override directory for report templates.",
        json_schema_extra=restricted(),
    )
    min_severity: Severity = Field(
        default=Severity.INFO, description="Findings below this are summarised, not detailed."
    )
    snippet_context_lines: Annotated[int, in_range(0, 20, "reporting.snippet_context_lines")] = (
        Field(
            default=3,
            description="Lines shown around each evidence line.",
            json_schema_extra=bounds(0, 20),
        )
    )
    include_privacy_attestation: bool = Field(
        default=True, description="Include the section showing what left the environment."
    )
    compliance: Annotated[
        list[ComplianceFramework], _enum_list(ComplianceFramework, "reporting.compliance")
    ] = Field(
        default_factory=lambda: [
            ComplianceFramework.owasp_top10,
            ComplianceFramework.cwe_top25,
            ComplianceFramework.pci_dss,
            ComplianceFramework.iso27001,
            ComplianceFramework.nist_ssdf,
        ],
        description="Compliance frameworks findings are mapped to.",
    )

    @field_validator("formats")
    @classmethod
    def _formats_not_empty(cls, value: list[ReportFormat]) -> list[ReportFormat]:
        if not value:
            raise ValueError(f"{INVALID} reporting.formats must name at least one format")
        return value

    @field_validator("title")
    @classmethod
    def _check_title(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_length("reporting.title", value, MAX_TEXT_LENGTH)

    @field_validator("auditor")
    @classmethod
    def _check_auditor(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _check_length("reporting.auditor", value, MAX_TEXT_LENGTH)

    @field_validator("classification")
    @classmethod
    def _check_classification(cls, value: str) -> str:
        return _check_length("reporting.classification", value, MAX_CLASSIFICATION_LENGTH)

    @field_validator("logo")
    @classmethod
    def _check_logo(cls, value: Path | None) -> Path | None:
        if value is not None and value.suffix.lower() not in LOGO_SUFFIXES:
            raise ValueError(f"{INVALID} reporting.logo must be a .png or .svg file")
        return value
