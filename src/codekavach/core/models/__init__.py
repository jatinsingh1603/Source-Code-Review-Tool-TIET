"""Domain models.

Finding, Location, CodeRegion, TaintPath, Evidence, Candidate, Scan, Project and related types.

Owning epic: E02. Normative layout: docs/ARCHITECTURE.md section 3.
"""

from codekavach.core.models.base import DataClassification, KavachModel, VersionedModel
from codekavach.core.models.canonical import canonical_json, sha256_hex
from codekavach.core.models.errors import (
    FingerprintInputError,
    InvalidStatusTransition,
    MigrationError,
    ModelError,
    UnsupportedSchemaVersion,
)
from codekavach.core.models.timeutil import UtcDatetime, utc_now

__all__ = [
    "DataClassification",
    "FingerprintInputError",
    "InvalidStatusTransition",
    "KavachModel",
    "MigrationError",
    "ModelError",
    "UnsupportedSchemaVersion",
    "UtcDatetime",
    "VersionedModel",
    "canonical_json",
    "sha256_hex",
    "utc_now",
]
