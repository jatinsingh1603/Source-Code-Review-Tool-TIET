from enum import StrEnum
from itertools import product

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from codekavach.core.models import (
    CandidateKind,
    Confidence,
    FindingStatus,
    KavachModel,
    Language,
    PrivacyLevel,
    ScanStatus,
    Severity,
    SliceStrategy,
    StageStatus,
    TaintRole,
)
from codekavach.core.models.enums import PlaceholderKind, SegmentRole, StubReason

GOLDEN: dict[type[StrEnum], list[str]] = {
    Severity: ["info", "low", "medium", "high", "critical"],
    Confidence: ["low", "medium", "high"],
    PrivacyLevel: ["L1", "L2", "L3", "L4", "L0"],
    FindingStatus: [
        "open",
        "confirmed",
        "false_positive",
        "accepted_risk",
        "suppressed",
        "fixed",
    ],
    Language: [
        "python",
        "javascript",
        "typescript",
        "java",
        "kotlin",
        "c",
        "cpp",
        "php",
        "go",
        "csharp",
        "ruby",
        "dockerfile",
        "terraform",
        "yaml",
        "json",
        "toml",
        "xml",
        "shell",
        "sql",
        "html",
        "unknown",
    ],
    TaintRole: ["source", "propagator", "sanitiser", "sink"],
    SliceStrategy: ["enclosing_function", "taint_path", "backward_slice"],
    CandidateKind: ["vulnerability", "secret", "dependency", "misconfiguration", "hotspot"],
    ScanStatus: [
        "pending",
        "running",
        "completed",
        "completed_with_errors",
        "failed",
        "cancelled",
    ],
    StageStatus: ["pending", "running", "succeeded", "failed", "skipped"],
    SegmentRole: ["primary", "taint_step", "context", "imports", "definition"],
    StubReason: ["out_of_slice_callee", "token_budget", "external_library"],
    PlaceholderKind: ["SECRET", "PII", "TERM"],
}


@pytest.mark.parametrize("enum", list(GOLDEN), ids=lambda e: e.__name__)
def test_member_values_match_golden_list(enum: type[StrEnum]) -> None:
    assert [member.value for member in enum] == GOLDEN[enum]


# ordering


def test_severity_ordering() -> None:
    assert Severity.HIGH > Severity.LOW
    assert max(Severity) is Severity.CRITICAL
    assert min(Severity) is Severity.INFO
    assert sorted([Severity.CRITICAL, Severity.INFO, Severity.MEDIUM]) == [
        Severity.INFO,
        Severity.MEDIUM,
        Severity.CRITICAL,
    ]


def test_confidence_ordering() -> None:
    assert Confidence.LOW < Confidence.MEDIUM < Confidence.HIGH
    assert max(Confidence) is Confidence.HIGH


def test_privacy_ordering_examples() -> None:
    assert sorted([PrivacyLevel.L3, PrivacyLevel.L1]) == [PrivacyLevel.L1, PrivacyLevel.L3]
    assert PrivacyLevel.L4 < PrivacyLevel.L0
    assert max(PrivacyLevel) is PrivacyLevel.L0
    assert PrivacyLevel.strictest(PrivacyLevel.L0, PrivacyLevel.L3) is PrivacyLevel.L0


STRICTNESS = [PrivacyLevel.L1, PrivacyLevel.L2, PrivacyLevel.L3, PrivacyLevel.L4, PrivacyLevel.L0]


@pytest.mark.parametrize(("a", "b"), list(product(STRICTNESS, STRICTNESS)))
def test_privacy_all_pairs(a: PrivacyLevel, b: PrivacyLevel) -> None:
    ia, ib = STRICTNESS.index(a), STRICTNESS.index(b)
    assert (a < b) == (ia < ib)
    assert (a <= b) == (ia <= ib)
    assert (a > b) == (ia > ib)
    assert (a >= b) == (ia >= ib)
    assert PrivacyLevel.strictest(a, b) is STRICTNESS[max(ia, ib)]


@pytest.mark.parametrize("level", STRICTNESS)
def test_l0_is_strictest_against_every_level(level: PrivacyLevel) -> None:
    assert PrivacyLevel.strictest(PrivacyLevel.L0, level) is PrivacyLevel.L0
    assert PrivacyLevel.strictest(level, PrivacyLevel.L0) is PrivacyLevel.L0


@given(st.sampled_from(PrivacyLevel), st.sampled_from(PrivacyLevel))
def test_strictest_is_commutative_and_dominant(a: PrivacyLevel, b: PrivacyLevel) -> None:
    result = PrivacyLevel.strictest(a, b)
    assert result is PrivacyLevel.strictest(b, a)
    assert result >= a
    assert result >= b


def test_strictest_needs_arguments() -> None:
    with pytest.raises(ValueError, match="at least one"):
        PrivacyLevel.strictest()


@pytest.mark.parametrize(
    "compare",
    [
        lambda: Severity.HIGH < "low",
        lambda: Severity.HIGH >= "critical",
        lambda: "low" > Severity.HIGH,  # noqa: SIM300 - reflected comparison is the case under test
        lambda: Severity.LOW < Confidence.HIGH,
        lambda: PrivacyLevel.L1 <= Severity.LOW,
    ],
)
def test_mixed_comparison_raises(compare: object) -> None:
    assert callable(compare)
    with pytest.raises(TypeError):
        compare()


def test_members_remain_hashable_and_equal_to_value() -> None:
    assert {Severity.HIGH: 1}["high"] == 1  # type: ignore[index]  # str key lookup at runtime
    assert Severity.HIGH == "high"  # type: ignore[comparison-overlap]  # StrEnum equals its value at runtime


def test_rank() -> None:
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]
    assert PrivacyLevel.L0.rank == 4


# helpers


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_from_cvss_score_boundaries(score: float, expected: Severity) -> None:
    assert Severity.from_cvss_score(score) is expected


@pytest.mark.parametrize("score", [-0.1, 10.1, float("nan")])
def test_from_cvss_score_out_of_range(score: float) -> None:
    with pytest.raises(ValueError, match="CVSS"):
        Severity.from_cvss_score(score)


def test_sarif_levels() -> None:
    assert [s.to_sarif_level() for s in Severity] == ["note", "note", "warning", "error", "error"]
    assert Severity.from_sarif_level("error") is Severity.HIGH
    assert Severity.from_sarif_level("warning") is Severity.MEDIUM
    assert Severity.from_sarif_level("note") is Severity.LOW
    assert Severity.from_sarif_level("none") is Severity.INFO
    with pytest.raises(ValueError, match="SARIF"):
        Severity.from_sarif_level("fatal")


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Confidence.LOW),
        (0.49, Confidence.LOW),
        (0.5, Confidence.MEDIUM),
        (0.79, Confidence.MEDIUM),
        (0.8, Confidence.HIGH),
        (1.0, Confidence.HIGH),
    ],
)
def test_confidence_from_score(score: float, expected: Confidence) -> None:
    assert Confidence.from_score(score) is expected


@pytest.mark.parametrize("score", [-0.01, 1.01, float("nan")])
def test_confidence_from_score_out_of_range(score: float) -> None:
    with pytest.raises(ValueError, match="confidence"):
        Confidence.from_score(score)


def test_privacy_properties() -> None:
    assert [lvl.sends_code for lvl in STRICTNESS] == [True, True, True, False, False]
    assert [lvl.sends_nothing_external for lvl in STRICTNESS] == [False] * 4 + [True]
    assert [lvl.is_abstract for lvl in STRICTNESS] == [False, False, False, True, False]


def test_language_helpers() -> None:
    assert Language.CPP.display_name == "C++"
    assert Language.CSHARP.display_name == "C#"
    assert Language.JAVASCRIPT.display_name == "JavaScript"
    assert all(lang.display_name for lang in Language)
    not_programming = {lang for lang in Language if not lang.is_programming_language}
    assert {lang.value for lang in not_programming} == {
        "dockerfile",
        "terraform",
        "yaml",
        "json",
        "toml",
        "xml",
        "unknown",
    }


def test_finding_status_terminal_for_sync() -> None:
    terminal = {s.value for s in FindingStatus if s.is_terminal_for_sync}
    assert terminal == {"false_positive", "accepted_risk", "suppressed", "fixed"}


# pydantic


class Holder(KavachModel):
    severity: Severity
    confidence: Confidence
    privacy: PrivacyLevel
    status: FindingStatus
    language: Language
    role: TaintRole
    strategy: SliceStrategy
    kind: CandidateKind
    scan: ScanStatus
    stage: StageStatus


def test_severity_json_validation() -> None:
    class Only(KavachModel):
        severity: Severity

    assert Only.model_validate_json('{"severity":"high"}').severity is Severity.HIGH
    for bad in ("HIGH", "severe"):
        with pytest.raises(ValidationError):
            Only.model_validate_json(f'{{"severity":"{bad}"}}')
    assert Only(severity=Severity.HIGH).model_dump_json() == '{"severity":"high"}'


def test_json_round_trip_of_every_enum() -> None:
    holder = Holder(
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        privacy=PrivacyLevel.L0,
        status=FindingStatus.ACCEPTED_RISK,
        language=Language.CSHARP,
        role=TaintRole.SANITISER,
        strategy=SliceStrategy.BACKWARD_SLICE,
        kind=CandidateKind.MISCONFIGURATION,
        scan=ScanStatus.COMPLETED_WITH_ERRORS,
        stage=StageStatus.SKIPPED,
    )
    restored = Holder.model_validate_json(holder.model_dump_json())
    assert restored == holder
    assert restored.privacy is PrivacyLevel.L0
