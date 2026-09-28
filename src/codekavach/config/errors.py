"""Configuration error codes, issues and exceptions.

Owning epic: E03.

Codes are stable: they are never renumbered, because users search for them. A new code is added
only together with an entry in ``docs/configuration/error-codes.md`` (E03-40 enforces this).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Literal, Self

Severity = Literal["error", "warning"]


class ConfigErrorCode(StrEnum):
    """Stable ``CK-CFG-nnn`` codes.

    Blocks: 00x files and syntax, 01x secrets, 02x profiles, 03x semantic rules, 04x project
    trust, 05x organisation policy, 06x environment and CLI overrides, 07x locations.
    """

    CK_CFG_001 = "CK-CFG-001"  # TOML syntax error
    CK_CFG_002 = "CK-CFG-002"  # unknown key
    CK_CFG_003 = "CK-CFG-003"  # invalid value (type, range, enum)
    CK_CFG_004 = "CK-CFG-004"  # unsupported config_version
    CK_CFG_005 = "CK-CFG-005"  # file missing, unreadable, too large, not UTF-8 or unsafe
    CK_CFG_006 = "CK-CFG-006"  # deprecated key (warning)
    CK_CFG_010 = "CK-CFG-010"  # plaintext secret in configuration
    CK_CFG_011 = "CK-CFG-011"  # malformed secret reference
    CK_CFG_012 = "CK-CFG-012"  # secret reference cannot be resolved
    CK_CFG_013 = "CK-CFG-013"  # secret file permissions too open (warning)
    CK_CFG_014 = "CK-CFG-014"  # insecure keyring backend
    CK_CFG_020 = "CK-CFG-020"  # unknown profile
    CK_CFG_021 = "CK-CFG-021"  # profile inheritance cycle or unknown parent
    CK_CFG_022 = "CK-CFG-022"  # user-defined profile shadows a built-in profile
    CK_CFG_030 = "CK-CFG-030"  # default provider not defined or disabled
    CK_CFG_031 = "CK-CFG-031"  # remote provider selected while llm.allow_remote is false
    CK_CFG_032 = "CK-CFG-032"  # level L0 with a remote provider
    CK_CFG_033 = "CK-CFG-033"  # a field required for this kind or mode is missing
    CK_CFG_034 = "CK-CFG-034"  # insecure or malformed URL
    CK_CFG_035 = "CK-CFG-035"  # engine both enabled and disabled
    CK_CFG_036 = "CK-CFG-036"  # integration feature enabled without its prerequisites
    CK_CFG_037 = "CK-CFG-037"  # privacy level below privacy.min_level
    CK_CFG_038 = "CK-CFG-038"  # public provider tier below L3 (warning)
    CK_CFG_039 = "CK-CFG-039"  # invalid path rule or glob
    CK_CFG_040 = "CK-CFG-040"  # restricted key in untrusted project configuration
    CK_CFG_041 = "CK-CFG-041"  # project configuration loosens a tighten-only setting
    CK_CFG_042 = "CK-CFG-042"  # trust store unreadable or corrupt
    CK_CFG_050 = "CK-CFG-050"  # organisation policy unreadable or invalid
    CK_CFG_051 = "CK-CFG-051"  # organisation policy located inside the project root
    CK_CFG_052 = "CK-CFG-052"  # organisation policy has unsafe ownership or permissions
    CK_CFG_053 = "CK-CFG-053"  # organisation policy hash mismatch
    CK_CFG_054 = "CK-CFG-054"  # organisation policy signature missing or invalid
    CK_CFG_055 = "CK-CFG-055"  # organisation policy violation
    CK_CFG_056 = "CK-CFG-056"  # organisation policy expired
    CK_CFG_060 = "CK-CFG-060"  # unknown or malformed CODEKAVACH_* variable
    CK_CFG_061 = "CK-CFG-061"  # malformed or conflicting --set override
    CK_CFG_070 = "CK-CFG-070"  # unsafe state_dir or output_dir location


_WARNINGS = frozenset(
    {ConfigErrorCode.CK_CFG_006, ConfigErrorCode.CK_CFG_013, ConfigErrorCode.CK_CFG_038}
)
DEFAULT_SEVERITY: Mapping[ConfigErrorCode, Severity] = MappingProxyType(
    {code: ("warning" if code in _WARNINGS else "error") for code in ConfigErrorCode}
)


@dataclass(frozen=True, slots=True)
class ConfigIssue:
    """One configuration problem.

    Rule for message authors: a message names keys, files, lines and counts; it never contains
    the value the user supplied, because that value may be a mis-pasted credential or a client's
    business term (CWE-532).
    """

    code: ConfigErrorCode
    severity: Severity
    message: str
    key: str | None = None
    source: str | None = None
    line: int | None = None
    hint: str | None = None

    def to_dict(self) -> dict[str, str | int | None]:
        """The JSON form used by ``codekavach config validate --format json``."""
        return {
            "code": self.code.value,
            "severity": self.severity,
            "message": self.message,
            "key": self.key,
            "source": self.source,
            "line": self.line,
            "hint": self.hint,
        }


def _render_one(issue: ConfigIssue) -> str:
    text = issue.code.value
    text += f" {issue.key}: {issue.message}" if issue.key else f" {issue.message}"
    if issue.source:
        location = issue.source if issue.line is None else f"{issue.source}:{issue.line}"
        text += f" ({location})"
    return text


def render_issues_plain(issues: Sequence[ConfigIssue]) -> str:
    """One line per issue: ``CK-CFG-003 scan.jobs: must be ... (/repo/codekavach.toml:12)``."""
    return "\n".join(_render_one(issue) for issue in issues)


class ConfigError(Exception):
    """Base class of configuration errors; always carries at least one ConfigIssue.

    Configuration errors are usage errors: the CLI maps them to ``ExitCode.USAGE`` (2, E05-04).
    This package does not import the CLI.
    """

    def __init__(self, issues: Sequence[ConfigIssue]) -> None:
        if not issues:
            raise ValueError("a ConfigError needs at least one issue")
        self.issues: tuple[ConfigIssue, ...] = tuple(issues)
        super().__init__(render_issues_plain(self.issues))

    @property
    def code(self) -> ConfigErrorCode:
        """The code of the first error-severity issue (or of the first issue)."""
        for issue in self.issues:
            if issue.severity == "error":
                return issue.code
        return self.issues[0].code

    def __str__(self) -> str:
        # Imported at call time: ``diagnostics`` imports this module.
        from codekavach.config.diagnostics import format_issues  # noqa: PLC0415

        return format_issues(self.issues)

    @classmethod
    def single(
        cls,
        code: ConfigErrorCode,
        message: str,
        *,
        key: str | None = None,
        source: str | None = None,
        line: int | None = None,
        hint: str | None = None,
    ) -> Self:
        """Build an error with one issue of the code's default severity."""
        issue = ConfigIssue(
            code=code,
            severity=DEFAULT_SEVERITY[code],
            message=message,
            key=key,
            source=source,
            line=line,
            hint=hint,
        )
        return cls([issue])


class ConfigSyntaxError(ConfigError):
    """A configuration file is not valid TOML."""


class ConfigValidationError(ConfigError):
    """Configuration values fail validation."""


class PlaintextSecretError(ConfigError):
    """A secret is written in plain text instead of a secret reference."""


class SecretResolutionError(ConfigError):
    """A secret reference cannot be resolved."""


class ProfileError(ConfigError):
    """A profile is unknown or its inheritance is invalid."""


class ProjectTrustError(ConfigError):
    """An untrusted project configuration sets a restricted or loosening key."""


class OrgPolicyError(ConfigError):
    """The organisation policy is invalid, unsafe or violated."""
