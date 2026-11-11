"""A Pydantic subset of SARIF 2.1.0 (E14-02).

Owning epic: E14. Everything here is raw data: SARIF logs quote client code in messages and
snippets (invariant I2). Unknown fields are ignored so that newer SARIF drafts still load, and
``region.snippet`` is not modelled at all, so snippet text never enters a Candidate. Every field is
optional because engines omit what they like; ``validate_log`` reports what is structurally
required, and ``ingest`` decides what a usable result needs.

The models are built in ``sarif-om``'s place, which has not been released since 2019.
"""

from typing import Any, ClassVar

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from codekavach.core.models.base import DataClassification, KavachModel


class SarifModel(KavachModel):
    """Base of the SARIF models: camelCase names in the file, unknown fields tolerated."""

    DATA_CLASSIFICATION: ClassVar[DataClassification] = DataClassification.RAW
    model_config = ConfigDict(extra="ignore", alias_generator=to_camel, populate_by_name=True)


class Message(SarifModel):
    """A ``message`` or ``multiformatMessageString``."""

    text: str | None = None
    markdown: str | None = None
    id: str | None = None


class ArtifactLocation(SarifModel):
    """Where an artifact is: a URI, maybe relative to a named base, or an ``artifacts`` index."""

    uri: str | None = None
    uri_base_id: str | None = None
    index: int | None = None


class Region(SarifModel):
    """A span, 1-based. ``snippet`` is deliberately not modelled."""

    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None


class PhysicalLocation(SarifModel):
    """A file and a region of it."""

    artifact_location: ArtifactLocation | None = None
    region: Region | None = None


class LogicalLocation(SarifModel):
    """A named program element, such as a function."""

    name: str | None = None
    fully_qualified_name: str | None = None
    kind: str | None = None


class Location(SarifModel):
    """One location of a result or of a code-flow step."""

    physical_location: PhysicalLocation | None = None
    logical_locations: tuple[LogicalLocation, ...] = ()
    message: Message | None = None


class ToolComponentReference(SarifModel):
    """A reference to the driver or an extension (or a taxonomy)."""

    name: str | None = None
    index: int | None = None
    guid: str | None = None


class ReportingDescriptorReference(SarifModel):
    """A reference to a rule or taxon."""

    id: str | None = None
    index: int | None = None
    tool_component: ToolComponentReference | None = None


class ReportingDescriptorRelationship(SarifModel):
    """A relationship from a rule to a taxon, which is how CodeQL links a rule to a CWE."""

    target: ReportingDescriptorReference | None = None


class DefaultConfiguration(SarifModel):
    """The rule's default ``level``."""

    level: str | None = None


class ReportingDescriptor(SarifModel):
    """A rule or a taxon."""

    id: str | None = None
    name: str | None = None
    short_description: Message | None = None
    full_description: Message | None = None
    help_uri: str | None = None
    default_configuration: DefaultConfiguration | None = None
    relationships: tuple[ReportingDescriptorRelationship, ...] = ()
    properties: dict[str, Any] = Field(default_factory=dict)


class ToolComponent(SarifModel):
    """The driver, an extension, or a taxonomy."""

    name: str | None = None
    version: str | None = None
    semantic_version: str | None = None
    rules: tuple[ReportingDescriptor, ...] = ()
    taxa: tuple[ReportingDescriptor, ...] = ()


class Tool(SarifModel):
    """The tool that produced a run."""

    driver: ToolComponent | None = None
    extensions: tuple[ToolComponent, ...] = ()


class Suppression(SarifModel):
    """A suppression of a result; what it means belongs to E21."""

    kind: str | None = None
    status: str | None = None
    justification: str | None = None


class ThreadFlowLocation(SarifModel):
    """One step of a thread flow."""

    location: Location | None = None
    importance: str | None = None
    nesting_level: int | None = None
    kinds: tuple[str, ...] = ()
    properties: dict[str, Any] = Field(default_factory=dict)


class ThreadFlow(SarifModel):
    """The steps of one thread, in execution order unless the engine reports sink first."""

    locations: tuple[ThreadFlowLocation, ...] = ()


class CodeFlow(SarifModel):
    """A data or control flow made of thread flows."""

    thread_flows: tuple[ThreadFlow, ...] = ()


class Result(SarifModel):
    """One finding."""

    rule_id: str | None = None
    rule: ReportingDescriptorReference | None = None
    rule_index: int | None = None
    level: str | None = None
    kind: str | None = None
    message: Message | None = None
    locations: tuple[Location, ...] = ()
    code_flows: tuple[CodeFlow, ...] = ()
    taxa: tuple[ReportingDescriptorReference, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    partial_fingerprints: dict[str, str] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)


class Artifact(SarifModel):
    """An entry of ``run.artifacts``."""

    location: ArtifactLocation | None = None


class AutomationDetails(SarifModel):
    """The run's identity as the producer states it."""

    id: str | None = None


class Run(SarifModel):
    """One run of one tool."""

    tool: Tool | None = None
    results: tuple[Result, ...] = ()
    artifacts: tuple[Artifact, ...] = ()
    original_uri_base_ids: dict[str, ArtifactLocation] = Field(default_factory=dict)
    column_kind: str | None = None
    taxonomies: tuple[ToolComponent, ...] = ()
    automation_details: AutomationDetails | None = None


class SarifLog(SarifModel):
    """A SARIF log."""

    version: str | None = None
    runs: tuple[Run, ...] | None = None
