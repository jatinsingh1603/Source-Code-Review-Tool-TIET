from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.config import Settings
from codekavach.config.models.reporting import (
    ComplianceFramework,
    ReportFormat,
    ReportingSettings,
)
from codekavach.core.models import Severity


def message(error: ValidationError) -> str:
    details = error.errors()[0]
    return str(details.get("ctx", {}).get("error", details["msg"]))


def test_defaults() -> None:
    reporting = Settings().reporting
    assert reporting.formats == [ReportFormat.html, ReportFormat.sarif, ReportFormat.json]
    assert reporting.output_dir == Path("codekavach-report")
    assert reporting.title is None
    assert reporting.classification == "Confidential"
    assert reporting.auditor is None
    assert reporting.logo is None
    assert reporting.template_dir is None
    assert reporting.min_severity is Severity.INFO
    assert reporting.snippet_context_lines == 3
    assert reporting.include_privacy_attestation is True
    assert reporting.compliance == [
        ComplianceFramework.owasp_top10,
        ComplianceFramework.cwe_top25,
        ComplianceFramework.pci_dss,
        ComplianceFramework.iso27001,
        ComplianceFramework.nist_ssdf,
    ]


def test_example_input() -> None:
    settings = Settings.model_validate(
        {"reporting": {"formats": "html,pdf", "snippet_context_lines": 5}}
    )
    assert settings.reporting.formats == [ReportFormat.html, ReportFormat.pdf]
    assert settings.reporting.snippet_context_lines == 5


def test_duplicates_removed_in_order() -> None:
    reporting = ReportingSettings.model_validate(
        {"formats": "html,pdf,html", "compliance": ["rbi", "sebi", "rbi"]}
    )
    assert reporting.formats == [ReportFormat.html, ReportFormat.pdf]
    assert reporting.compliance == [ComplianceFramework.rbi, ComplianceFramework.sebi]


def test_enum_member_names_follow_values() -> None:
    for enum in (ReportFormat, ComplianceFramework):
        for member in enum:
            assert member.name == member.value.replace("-", "_")


@pytest.mark.parametrize(
    "data",
    [
        {"formats": []},
        {"formats": ""},
        {"formats": ["png"]},
        {"compliance": ["gdpr"]},
        {"snippet_context_lines": 21},
        {"snippet_context_lines": -1},
        {"logo": "cover.jpg"},
        {"logo": "cover"},
        {"classification": ""},
        {"classification": "x" * 61},
        {"title": "x" * 201},
        {"auditor": ""},
    ],
)
def test_invalid_values(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as error:
        ReportingSettings.model_validate(data)
    assert message(error.value).startswith("[CK-CFG-003]")


@pytest.mark.parametrize("logo", ["cover.png", "COVER.SVG", "img/logo.Png"])
def test_logo_suffix_case_insensitive(logo: str) -> None:
    assert ReportingSettings.model_validate({"logo": logo}).logo == Path(logo)


def test_every_enum_value_round_trips() -> None:
    reporting = ReportingSettings.model_validate(
        {"formats": list(ReportFormat), "compliance": list(ComplianceFramework)}
    )
    dumped = reporting.model_dump(mode="json")
    assert dumped["formats"] == [member.value for member in ReportFormat]
    assert dumped["compliance"] == [member.value for member in ComplianceFramework]
    assert ReportingSettings.model_validate(dumped) == reporting


def test_markers_in_json_schema() -> None:
    schema = Settings.model_json_schema()
    properties = schema["$defs"]["ReportingSettings"]["properties"]
    assert properties["template_dir"]["x-ck-restricted"] is True
    assert properties["output_dir"]["x-ck-volatile"] is True


def test_no_image_evidence_fields() -> None:
    for name in ReportingSettings.model_fields:
        assert not any(word in name for word in ("screenshot", "video", "image_evidence"))


text = st.text(st.characters(codec="ascii", categories=("L", "N")), min_size=1, max_size=60)


@given(
    formats=st.lists(st.sampled_from(list(ReportFormat)), min_size=1, unique=True),
    compliance=st.lists(st.sampled_from(list(ComplianceFramework)), unique=True),
    lines=st.integers(0, 20),
    title=st.none() | text,
    classification=text,
    severity=st.sampled_from(list(Severity)),
    attestation=st.booleans(),
    logo=st.none() | st.sampled_from(["a.png", "b/c.svg"]),
)
def test_property_json_round_trip(  # noqa: PLR0917 - one argument per strategy
    formats: list[ReportFormat],
    compliance: list[ComplianceFramework],
    lines: int,
    title: str | None,
    classification: str,
    severity: Severity,
    attestation: bool,
    logo: str | None,
) -> None:
    reporting = ReportingSettings.model_validate(
        {
            "formats": formats,
            "compliance": compliance,
            "snippet_context_lines": lines,
            "title": title,
            "classification": classification,
            "min_severity": severity,
            "include_privacy_attestation": attestation,
            "logo": logo,
        }
    )
    assert ReportingSettings.model_validate(reporting.model_dump(mode="json")) == reporting
