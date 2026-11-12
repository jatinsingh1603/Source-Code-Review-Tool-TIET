"""Document control: classification, version history, distribution and sign-off.

Owning epic: E30 (E30-01).
"""

from typing import ClassVar, Literal

from codekavach.core.models.base import DataClassification, KavachModel

DISCLAIMER = (
    "This report presents the results of an automated, model-assisted secure source code review "
    "of the code version identified in the scope section, at the date of the review. It is not a "
    "guarantee that the code is free of further vulnerabilities: automated analysis has known "
    "false-negative rates, and findings should be read together with the limitations listed in "
    "the appendices. Model-assisted assessments are advisory and are recorded with the model and "
    "provider that produced them; no finding was dismissed by a model."
)


class Classification(KavachModel):
    """The handling marking printed on every page."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    label: str = "Confidential"
    banner: str = "CONFIDENTIAL"
    handling_note: str = (
        "Contains security-sensitive information about the client's systems. Distribute only to "
        "the named recipients; do not forward outside the engagement."
    )


class VersionEntry(KavachModel):
    """One line of the version history."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    version: str
    date: str
    author: str
    change: str
    state: Literal["draft", "final"] = "final"


class DistributionEntry(KavachModel):
    """One recipient of the report."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    name: str
    role: str
    organisation: str


class SignOff(KavachModel):
    """One approval of the report."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    name: str
    role: str
    date: str = ""
    signed: bool = False


class DocumentControl(KavachModel):
    """The document-control page."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.METADATA

    report_id: str
    version: str = "1.0"
    issue_date: str
    prepared_by: str
    prepared_for: str
    classification: Classification = Classification()
    versions: tuple[VersionEntry, ...] = ()
    distribution: tuple[DistributionEntry, ...] = ()
    reviewers: tuple[str, ...] = ()
    sign_offs: tuple[SignOff, ...] = ()
    copyright_notice: str = ""
    disclaimer: str = DISCLAIMER
