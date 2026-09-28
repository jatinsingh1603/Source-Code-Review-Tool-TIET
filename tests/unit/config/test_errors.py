import dataclasses
import json
import re

import pytest

from codekavach.config import ConfigError, ConfigErrorCode, ConfigIssue
from codekavach.config.diagnostics import format_issues
from codekavach.config.errors import (
    DEFAULT_SEVERITY,
    ConfigSyntaxError,
    ConfigValidationError,
    OrgPolicyError,
    PlaintextSecretError,
    ProfileError,
    ProjectTrustError,
    SecretResolutionError,
    render_issues_plain,
)

GOLDEN_CODES = [
    "CK-CFG-001",
    "CK-CFG-002",
    "CK-CFG-003",
    "CK-CFG-004",
    "CK-CFG-005",
    "CK-CFG-006",
    "CK-CFG-010",
    "CK-CFG-011",
    "CK-CFG-012",
    "CK-CFG-013",
    "CK-CFG-014",
    "CK-CFG-020",
    "CK-CFG-021",
    "CK-CFG-022",
    "CK-CFG-030",
    "CK-CFG-031",
    "CK-CFG-032",
    "CK-CFG-033",
    "CK-CFG-034",
    "CK-CFG-035",
    "CK-CFG-036",
    "CK-CFG-037",
    "CK-CFG-038",
    "CK-CFG-039",
    "CK-CFG-040",
    "CK-CFG-041",
    "CK-CFG-042",
    "CK-CFG-050",
    "CK-CFG-051",
    "CK-CFG-052",
    "CK-CFG-053",
    "CK-CFG-054",
    "CK-CFG-055",
    "CK-CFG-056",
    "CK-CFG-060",
    "CK-CFG-061",
    "CK-CFG-070",
]
SUBCLASSES = [
    ConfigSyntaxError,
    ConfigValidationError,
    PlaintextSecretError,
    SecretResolutionError,
    ProfileError,
    ProjectTrustError,
    OrgPolicyError,
]


def issue(code: ConfigErrorCode, severity: str = "error", **kwargs: object) -> ConfigIssue:
    return ConfigIssue(code=code, severity=severity, message="broken", **kwargs)  # type: ignore[arg-type]


def test_golden_codes() -> None:
    assert [code.value for code in ConfigErrorCode] == GOLDEN_CODES
    assert len(GOLDEN_CODES) == 37
    for code in ConfigErrorCode:
        assert re.fullmatch(r"CK-CFG-\d{3}", code.value)
        assert code.name == code.value.replace("-", "_")


def test_default_severity_covers_every_code() -> None:
    assert set(DEFAULT_SEVERITY) == set(ConfigErrorCode)
    warnings = {code.value for code, severity in DEFAULT_SEVERITY.items() if severity == "warning"}
    assert warnings == {"CK-CFG-006", "CK-CFG-013", "CK-CFG-038"}


def test_error_needs_issues() -> None:
    with pytest.raises(ValueError, match="at least one"):
        ConfigError([])


def test_single_and_code() -> None:
    error = ConfigError.single(
        ConfigErrorCode.CK_CFG_003, "must be between 0 and 256", key="scan.jobs"
    )
    assert error.code is ConfigErrorCode.CK_CFG_003
    assert isinstance(error.issues, tuple)
    assert error.issues[0].severity == "error"


def test_code_skips_warnings() -> None:
    error = ConfigError(
        [
            issue(ConfigErrorCode.CK_CFG_006, "warning"),
            issue(ConfigErrorCode.CK_CFG_002),
            issue(ConfigErrorCode.CK_CFG_003),
        ]
    )
    assert error.code is ConfigErrorCode.CK_CFG_002
    only_warnings = ConfigError([issue(ConfigErrorCode.CK_CFG_038, "warning")])
    assert only_warnings.code is ConfigErrorCode.CK_CFG_038


@pytest.mark.parametrize("cls", SUBCLASSES, ids=lambda c: c.__name__)
def test_subclasses(cls: type[ConfigError]) -> None:
    error = cls.single(ConfigErrorCode.CK_CFG_001, "bad")
    assert isinstance(error, ConfigError)
    assert type(error) is cls
    assert cls.__doc__


def test_plain_rendering() -> None:
    error = ConfigError(
        [
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_003,
                severity="error",
                message="must be between 0 and 256",
                key="scan.jobs",
                source="/repo/codekavach.toml",
                line=12,
            ),
            ConfigIssue(
                code=ConfigErrorCode.CK_CFG_060,
                severity="error",
                message="unknown variable",
                source="CODEKAVACH_SCAN__JOBZ",
            ),
        ]
    )
    assert render_issues_plain(error.issues) == (
        "CK-CFG-003 scan.jobs: must be between 0 and 256 (/repo/codekavach.toml:12)\n"
        "CK-CFG-060 unknown variable (CODEKAVACH_SCAN__JOBZ)"
    )
    assert str(error) == format_issues(error.issues)


def test_issue_to_dict() -> None:
    data = issue(
        ConfigErrorCode.CK_CFG_002, key="scna", source="a.toml", line=3, hint="scan"
    ).to_dict()
    assert set(data) == {"code", "severity", "message", "key", "source", "line", "hint"}
    assert data["code"] == "CK-CFG-002"
    json.dumps(data)


def test_issue_is_frozen_and_hashable() -> None:
    value = issue(ConfigErrorCode.CK_CFG_001)
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.message = "x"  # type: ignore[misc]
    assert {value: 1}[issue(ConfigErrorCode.CK_CFG_001)] == 1
