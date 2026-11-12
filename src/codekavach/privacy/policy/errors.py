"""The error-code registry of the project privacy policy (``[CK-POL-001]`` to ``[CK-POL-009]``).

Owning epic: E25.

Every refusal of a ``codekavach.policy.toml`` raises ``PolicyError`` with one of the codes below.
A refusal never falls back to a default policy (invariant I4, fail closed). Messages may name the
policy file, a line, a level, a tag, a rule id or a pattern, because those are operator-authored
identifiers the operator needs to fix the file; they never quote scanned source.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Final


class PolicyErrorCode(StrEnum):
    """The stable codes of a policy refusal."""

    UNREADABLE = "CK-POL-001"
    SCHEMA_VERSION = "CK-POL-002"
    UNKNOWN_KEY = "CK-POL-003"
    BAD_PATTERN = "CK-POL-004"
    LEVEL_AND_NEVER_SEND = "CK-POL-005"
    BELOW_MIN_LEVEL = "CK-POL-006"
    TAG_WITHOUT_LEVEL = "CK-POL-007"
    TOO_MANY_RULES = "CK-POL-008"
    UNKNOWN_TIER = "CK-POL-009"


POLICY_ERROR_CODES: Final[dict[PolicyErrorCode, str]] = {
    PolicyErrorCode.UNREADABLE: (
        "the policy file is unreadable, oversized, not UTF-8 or valid TOML, a symbolic link, "
        "or outside the project root"
    ),
    PolicyErrorCode.SCHEMA_VERSION: "unknown policy_version",
    PolicyErrorCode.UNKNOWN_KEY: "unknown table or key, or a value of the wrong type",
    PolicyErrorCode.BAD_PATTERN: (
        "invalid pattern: empty, absolute, a .. segment, a backslash or longer than 256 characters"
    ),
    PolicyErrorCode.LEVEL_AND_NEVER_SEND: "a path rule must set exactly one of level or never_send",
    PolicyErrorCode.BELOW_MIN_LEVEL: "a level in the policy is weaker than privacy.min_level",
    PolicyErrorCode.TAG_WITHOUT_LEVEL: "a classification tag sets neither a level nor never_send",
    PolicyErrorCode.TOO_MANY_RULES: "more than 1,000 rules in total",
    PolicyErrorCode.UNKNOWN_TIER: "a provider trust tier that is not local, private or public",
}


class PolicyError(Exception):
    """A policy document is refused. ``code`` is the bare code, for example ``CK-POL-004``."""

    def __init__(
        self,
        code: PolicyErrorCode | str,
        message: str,
        *,
        file: Path | str | None = None,
        line: int | None = None,
        pattern: str | None = None,
    ) -> None:
        self.code = str(code)
        self.file = None if file is None else str(file)
        self.line = line
        self.pattern = pattern
        where = ""
        if self.file is not None:
            where = f" {self.file}" + ("" if line is None else f":{line}")
        elif line is not None:
            where = f" line {line}"
        super().__init__(f"[{self.code}]{where}: {message}")
