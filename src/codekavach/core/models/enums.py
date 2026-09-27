"""Shared enumerations of the domain model.

Owning epic: E02. The string values are part of the public JSON contract; never rename them
without a schema version bump. Ranked enums compare by rank (their definition order), not
alphabetically, and refuse comparison with plain strings or other enums.
"""

import math
from enum import StrEnum
from typing import Self


class _RankedStrEnum(StrEnum):
    """StrEnum whose members are ordered by definition order (first member lowest)."""

    @property
    def rank(self) -> int:
        """Position of the member in ascending order."""
        return list(type(self)).index(self)

    def _other_rank(self, other: object) -> int:
        if type(other) is not type(self):
            raise TypeError(
                f"cannot compare {type(self).__name__} with {type(other).__name__}; "
                "ranked enums compare only with members of the same enum"
            )
        return type(self)(other).rank

    def __lt__(self, other: object) -> bool:
        return self.rank < self._other_rank(other)

    def __le__(self, other: object) -> bool:
        return self.rank <= self._other_rank(other)

    def __gt__(self, other: object) -> bool:
        return self.rank > self._other_rank(other)

    def __ge__(self, other: object) -> bool:
        return self.rank >= self._other_rank(other)

    __hash__ = StrEnum.__hash__


class Severity(_RankedStrEnum):
    """Severity of a candidate or finding, in ascending order."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss_score(cls, score: float) -> Self:
        """Map a CVSS v4.0 base score to its qualitative severity band."""
        if math.isnan(score) or not 0.0 <= score <= 10.0:
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        if score == 0.0:
            return cls("info")
        if score < 4.0:
            return cls("low")
        if score < 7.0:
            return cls("medium")
        if score < 9.0:
            return cls("high")
        return cls("critical")

    def to_sarif_level(self) -> str:
        """Return the SARIF ``level`` for this severity."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self is Severity.MEDIUM:
            return "warning"
        return "note"

    @classmethod
    def from_sarif_level(cls, level: str) -> Self:
        """Return the default severity for a SARIF ``level``; engines may refine it."""
        mapping = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
        if level not in mapping:
            raise ValueError("unknown SARIF level")
        return cls(mapping[level])


class Confidence(_RankedStrEnum):
    """Confidence in a candidate or verdict, in ascending order."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_score(cls, score: float) -> Self:
        """Map a score in [0, 1] to a confidence band."""
        if math.isnan(score) or not 0.0 <= score <= 1.0:
            raise ValueError("confidence score must be between 0.0 and 1.0")
        if score >= 0.8:
            return cls("high")
        if score >= 0.5:
            return cls("medium")
        return cls("low")


class PrivacyLevel(_RankedStrEnum):
    """Privacy level, ranked by strictness: L1 < L2 < L3 < L4 < L0 (L0 sends nothing)."""

    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    L0 = "L0"

    @classmethod
    def strictest(cls, *levels: "PrivacyLevel") -> "PrivacyLevel":
        """Return the strictest of ``levels``; the stricter level always wins."""
        if not levels:
            raise ValueError("strictest() needs at least one privacy level")
        return max(levels)

    @property
    def sends_code(self) -> bool:
        """True when (transformed) code leaves the machine: L1, L2 and L3."""
        return self in (PrivacyLevel.L1, PrivacyLevel.L2, PrivacyLevel.L3)

    @property
    def sends_nothing_external(self) -> bool:
        """True for L0: nothing leaves the machine."""
        return self is PrivacyLevel.L0

    @property
    def is_abstract(self) -> bool:
        """True for L4: only abstract data-flow facts leave the machine."""
        return self is PrivacyLevel.L4


class FindingStatus(StrEnum):
    """Lifecycle status of a finding (unordered; transitions are defined in E02-16)."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    SUPPRESSED = "suppressed"
    FIXED = "fixed"

    @property
    def is_terminal_for_sync(self) -> bool:
        """True for states in which the GitHub sync closes the issue."""
        return self in (
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.SUPPRESSED,
            FindingStatus.FIXED,
        )


_DISPLAY_NAMES = {
    "python": "Python",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "java": "Java",
    "kotlin": "Kotlin",
    "c": "C",
    "cpp": "C++",
    "php": "PHP",
    "go": "Go",
    "csharp": "C#",
    "ruby": "Ruby",
    "dockerfile": "Dockerfile",
    "terraform": "Terraform",
    "yaml": "YAML",
    "json": "JSON",
    "toml": "TOML",
    "xml": "XML",
    "shell": "Shell",
    "sql": "SQL",
    "html": "HTML",
    "unknown": "Unknown",
}
_NOT_PROGRAMMING = frozenset({"dockerfile", "terraform", "yaml", "json", "toml", "xml", "unknown"})


class Language(StrEnum):
    """Source language of a file (unordered)."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    KOTLIN = "kotlin"
    C = "c"
    CPP = "cpp"
    PHP = "php"
    GO = "go"
    CSHARP = "csharp"
    RUBY = "ruby"
    DOCKERFILE = "dockerfile"
    TERRAFORM = "terraform"
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    XML = "xml"
    SHELL = "shell"
    SQL = "sql"
    HTML = "html"
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        """Human-readable name, for example ``C++`` for ``cpp``."""
        return _DISPLAY_NAMES[self.value]

    @property
    def is_programming_language(self) -> bool:
        """False for configuration and data formats and for ``unknown``."""
        return self.value not in _NOT_PROGRAMMING


class TaintRole(StrEnum):
    """Role of a step in a taint path."""

    SOURCE = "source"
    PROPAGATOR = "propagator"
    SANITISER = "sanitiser"
    SINK = "sink"


class SliceStrategy(StrEnum):
    """Strategy used to extract a code slice."""

    ENCLOSING_FUNCTION = "enclosing_function"
    TAINT_PATH = "taint_path"
    BACKWARD_SLICE = "backward_slice"


class CandidateKind(StrEnum):
    """Kind of candidate produced by deterministic analysis."""

    VULNERABILITY = "vulnerability"
    SECRET = "secret"  # noqa: S105 - enum value naming a candidate kind, not a password
    DEPENDENCY = "dependency"
    MISCONFIGURATION = "misconfiguration"
    HOTSPOT = "hotspot"


class ScanStatus(StrEnum):
    """Status of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StageStatus(StrEnum):
    """Status of one pipeline stage run."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class SegmentRole(StrEnum):
    """Why a segment is part of a code slice."""

    PRIMARY = "primary"
    TAINT_STEP = "taint_step"
    CONTEXT = "context"
    IMPORTS = "imports"
    DEFINITION = "definition"


class StubReason(StrEnum):
    """Why a callee was replaced by a signature-only stub."""

    OUT_OF_SLICE_CALLEE = "out_of_slice_callee"
    TOKEN_BUDGET = "token_budget"  # noqa: S105 - enum value, not a credential
    EXTERNAL_LIBRARY = "external_library"


class PlaceholderKind(StrEnum):
    """Kind of redaction placeholder; upper case because it appears inside the token."""

    SECRET = "SECRET"  # noqa: S105 - enum value  # pragma: allowlist secret
    PII = "PII"
    TERM = "TERM"
