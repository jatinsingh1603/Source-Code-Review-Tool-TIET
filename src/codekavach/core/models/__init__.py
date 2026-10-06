"""Domain models: the public API of ``codekavach.core.models``.

Finding, Location, CodeRegion, TaintPath, Evidence, Candidate, Scan, Project, CodeSlice,
SanitisedPayload, LLMVerdict, EgressRecord and the related types, enums, ids and helpers. Import
from here, not from the submodules; ``__all__`` is curated, sorted and tested
(``tests/unit/core/models/test_public_api.py``). Reference: ``docs/reference/domain-model.md``.

Owning epic: E02. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.core.models.base import (
    DataClassification,
    KavachModel,
    VersionedModel,
)
from codekavach.core.models.candidate import (
    Candidate,
)
from codekavach.core.models.canonical import (
    canonical_json,
    sha256_hex,
)
from codekavach.core.models.egress import (
    EgressRecord,
    TokenCounts,
)
from codekavach.core.models.enums import (
    ActorKind,
    CandidateKind,
    Confidence,
    ContextKind,
    DetectionOrigin,
    EgressOutcome,
    EvidenceRole,
    FindingStatus,
    Language,
    PlaceholderKind,
    PrivacyLevel,
    ScanStatus,
    SegmentRole,
    Severity,
    SliceStrategy,
    StageStatus,
    StubReason,
    TaintRole,
    TrustTier,
)
from codekavach.core.models.errors import (
    FingerprintInputError,
    InvalidStatusTransition,
    MigrationError,
    ModelError,
    UnsupportedSchemaVersion,
)
from codekavach.core.models.evidence import (
    Evidence,
    HighlightRange,
    SnippetLine,
)
from codekavach.core.models.finding import (
    EngineRef,
    Finding,
    Impact,
    Likelihood,
    LLMReviewRef,
    Provenance,
)
from codekavach.core.models.fingerprint import (
    FingerprintParts,
    compute_correlation_key,
    compute_fingerprint,
    fingerprint_batch,
    normalise_snippet,
    snippet_hash,
)
from codekavach.core.models.ids import (
    CandidateId,
    CandidateIdField,
    FindingId,
    FindingIdField,
    PayloadId,
    PayloadIdField,
    ProjectId,
    ProjectIdField,
    ScanId,
    ScanIdField,
    SliceId,
    SliceIdField,
    UlidFactory,
    new_candidate_id,
    new_finding_id,
    new_payload_id,
    new_project_id,
    new_scan_id,
    new_slice_id,
    new_ulid,
)
from codekavach.core.models.lifecycle import (
    StatusChange,
    apply_transition,
    effective_status,
    validate_transition,
)
from codekavach.core.models.location import (
    CodeRegion,
    Location,
)
from codekavach.core.models.migrate import (
    load_versioned,
    migrate_document,
    register_migration,
)
from codekavach.core.models.paths import (
    RepoPath,
    normalise_repo_path,
)
from codekavach.core.models.payload import (
    LineMapEntry,
    PlaceholderRef,
    SanitisedPayload,
    find_placeholders,
    format_placeholder,
    parse_placeholder,
)
from codekavach.core.models.scan import (
    Project,
    Scan,
    StageResult,
)
from codekavach.core.models.slice import (
    CodeSlice,
    SliceSegment,
    Stub,
)
from codekavach.core.models.summary import (
    EgressTotals,
    ScanSummary,
)
from codekavach.core.models.taint import (
    TaintPath,
    TaintStep,
)
from codekavach.core.models.taxonomy import (
    CweId,
    Reference,
    TaxonomyRef,
    format_cwe,
    parse_cwe,
)
from codekavach.core.models.text import (
    RawCode,
    SanitisedText,
    split_lines,
)
from codekavach.core.models.timeutil import (
    UtcDatetime,
    utc_now,
)
from codekavach.core.models.verdict import (
    ContextRequest,
    LLMVerdict,
)

__all__ = [
    "ActorKind",
    "Candidate",
    "CandidateId",
    "CandidateIdField",
    "CandidateKind",
    "CodeRegion",
    "CodeSlice",
    "Confidence",
    "ContextKind",
    "ContextRequest",
    "CweId",
    "DataClassification",
    "DetectionOrigin",
    "EgressOutcome",
    "EgressRecord",
    "EgressTotals",
    "EngineRef",
    "Evidence",
    "EvidenceRole",
    "Finding",
    "FindingId",
    "FindingIdField",
    "FindingStatus",
    "FingerprintInputError",
    "FingerprintParts",
    "HighlightRange",
    "Impact",
    "InvalidStatusTransition",
    "KavachModel",
    "LLMReviewRef",
    "LLMVerdict",
    "Language",
    "Likelihood",
    "LineMapEntry",
    "Location",
    "MigrationError",
    "ModelError",
    "PayloadId",
    "PayloadIdField",
    "PlaceholderKind",
    "PlaceholderRef",
    "PrivacyLevel",
    "Project",
    "ProjectId",
    "ProjectIdField",
    "Provenance",
    "RawCode",
    "Reference",
    "RepoPath",
    "SanitisedPayload",
    "SanitisedText",
    "Scan",
    "ScanId",
    "ScanIdField",
    "ScanStatus",
    "ScanSummary",
    "SegmentRole",
    "Severity",
    "SliceId",
    "SliceIdField",
    "SliceSegment",
    "SliceStrategy",
    "SnippetLine",
    "StageResult",
    "StageStatus",
    "StatusChange",
    "Stub",
    "StubReason",
    "TaintPath",
    "TaintRole",
    "TaintStep",
    "TaxonomyRef",
    "TokenCounts",
    "TrustTier",
    "UlidFactory",
    "UnsupportedSchemaVersion",
    "UtcDatetime",
    "VersionedModel",
    "apply_transition",
    "canonical_json",
    "compute_correlation_key",
    "compute_fingerprint",
    "effective_status",
    "find_placeholders",
    "fingerprint_batch",
    "format_cwe",
    "format_placeholder",
    "load_versioned",
    "migrate_document",
    "new_candidate_id",
    "new_finding_id",
    "new_payload_id",
    "new_project_id",
    "new_scan_id",
    "new_slice_id",
    "new_ulid",
    "normalise_repo_path",
    "normalise_snippet",
    "parse_cwe",
    "parse_placeholder",
    "register_migration",
    "sha256_hex",
    "snippet_hash",
    "split_lines",
    "utc_now",
    "validate_transition",
]
