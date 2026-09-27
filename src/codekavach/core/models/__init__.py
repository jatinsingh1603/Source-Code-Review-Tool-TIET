"""Domain models.

Finding, Location, CodeRegion, TaintPath, Evidence, Candidate, Scan, Project and related types.

Owning epic: E02. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.canonical import canonical_json, sha256_hex
from codekavach.core.models.enums import (
    CandidateKind,
    Confidence,
    FindingStatus,
    Language,
    PrivacyLevel,
    ScanStatus,
    Severity,
    SliceStrategy,
    StageStatus,
    TaintRole,
)
from codekavach.core.models.errors import (
    FingerprintInputError,
    InvalidStatusTransition,
    MigrationError,
    ModelError,
    UnsupportedSchemaVersion,
)
from codekavach.core.models.taxonomy import CweId, format_cwe, parse_cwe
from codekavach.core.models.timeutil import UtcDatetime, utc_now

__all__ = [
    "CandidateKind",
    "Confidence",
    "CweId",
    "DataClassification",
    "FindingStatus",
    "FingerprintInputError",
    "InvalidStatusTransition",
    "KavachModel",
    "Language",
    "MigrationError",
    "ModelError",
    "PrivacyLevel",
    "ScanStatus",
    "Severity",
    "SliceStrategy",
    "StageStatus",
    "TaintRole",
    "UnsupportedSchemaVersion",
    "UtcDatetime",
    "VersionedModel",
    "canonical_json",
    "format_cwe",
    "parse_cwe",
    "sha256_hex",
    "utc_now",
]
