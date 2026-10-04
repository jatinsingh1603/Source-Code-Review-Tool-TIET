import itertools
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import pytest
from hypothesis import given
from hypothesis import strategies as st

from codekavach.cli.exit_codes import ExitCode
from codekavach.cli.scan import (
    CliScanResult,
    ThresholdResult,
    evaluate_threshold,
    exit_error,
    final_exit_code,
    threshold_lines,
)
from codekavach.core.models.enums import Confidence, FindingStatus, PrivacyLevel, Severity
from codekavach.core.models.finding import Finding, LLMReviewRef
from codekavach.core.models.ids import new_finding_id
from tests.support.cli import CliResult
from tests.support.factories import make_finding
from tests.support.scan_stub import install_stub

Cli = Callable[..., CliResult]
Threshold = Severity | Literal["none"]
THRESHOLDS: tuple[Threshold, ...] = (*Severity, "none")
COUNTED = (FindingStatus.OPEN, FindingStatus.CONFIRMED)
SERIAL = itertools.count(1)


def finding(severity: Severity, status: FindingStatus = FindingStatus.OPEN) -> Finding:
    return make_finding(
        id=new_finding_id(),
        fingerprint=f"ckfp1:{next(SERIAL):032x}",
        severity=severity,
        status=status,
    )


def cli_result(*, degraded: tuple[str, ...] = (), blocked: int = 0) -> CliScanResult:
    return CliScanResult(
        scan_id="scan_01ARYZ6S410000000000000000",
        status="completed",
        summary=None,
        report_files=(),
        degraded_stages=degraded,
        egress_sent=0,
        egress_blocked=blocked,
        state_dir=Path(".codekavach"),
        stages_run=1,
    )


# evaluate_threshold


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("threshold", THRESHOLDS)
def test_every_severity_against_every_threshold(severity: Severity, threshold: Threshold) -> None:
    result = evaluate_threshold([finding(severity)], threshold)
    expected = threshold != "none" and severity.rank >= Severity(threshold).rank
    assert result.exceeded is expected
    assert result.threshold == threshold
    assert result.counted_at_or_above == (1 if expected else 0)
    assert result.worst is severity
    assert result.not_counted == 0


@pytest.mark.parametrize("status", list(FindingStatus))
def test_only_open_and_confirmed_findings_count(status: FindingStatus) -> None:
    result = evaluate_threshold([finding(Severity.CRITICAL, status)], Severity.INFO)
    counted = status in COUNTED
    assert result.exceeded is counted
    assert result.counted_at_or_above == (1 if counted else 0)
    assert result.not_counted == (0 if counted else 1)
    assert result.worst is (Severity.CRITICAL if counted else None)


def test_counts_worst_and_generators() -> None:
    findings = [
        finding(Severity.HIGH),
        finding(Severity.LOW),
        finding(Severity.CRITICAL, FindingStatus.SUPPRESSED),
        finding(Severity.MEDIUM, FindingStatus.CONFIRMED),
    ]
    result = evaluate_threshold((item for item in findings), Severity.MEDIUM)
    assert result == ThresholdResult(True, Severity.MEDIUM, 2, Severity.HIGH, 1)
    assert evaluate_threshold([], Severity.INFO) == ThresholdResult(False, Severity.INFO, 0, None)
    disabled = evaluate_threshold(findings, "none")
    assert (disabled.exceeded, disabled.counted_at_or_above) == (False, 0)
    assert (disabled.fail_on, disabled.worst, disabled.not_counted) == ("none", Severity.HIGH, 1)


def test_an_llm_verdict_does_not_lower_the_gate() -> None:
    plain = finding(Severity.HIGH)
    dismissed = LLMReviewRef(
        provider="mock",
        model="mock-1",
        task="triage",
        level=PrivacyLevel.L3,
        is_vulnerable=False,
        confidence=Confidence.HIGH,
        reasoning="The model considers this a false positive.",
    )
    reviewed = plain.evolve(
        provenance=plain.provenance.evolve(llm_reviews=(dismissed,)).model_dump()
    )
    assert reviewed.provenance.llm_reviews[0].is_vulnerable is False
    for threshold in (Severity.HIGH, Severity.LOW):
        assert evaluate_threshold([reviewed], threshold) == evaluate_threshold([plain], threshold)
    result = evaluate_threshold([reviewed], Severity.HIGH)
    assert final_exit_code(cli_result(), result, strict=False, strict_privacy=False) == 1


severities = st.sampled_from(list(Severity))
statuses = st.sampled_from(list(FindingStatus))
finding_specs = st.lists(st.tuples(severities, statuses), max_size=8)


@given(specs=finding_specs, lower=severities, higher=severities)
def test_raising_the_threshold_never_makes_a_pass_fail(
    specs: list[tuple[Severity, FindingStatus]], lower: Severity, higher: Severity
) -> None:
    if lower.rank > higher.rank:
        lower, higher = higher, lower
    findings = [finding(severity, status) for severity, status in specs]
    if not evaluate_threshold(findings, lower).exceeded:
        assert not evaluate_threshold(findings, higher).exceeded
    assert not evaluate_threshold(findings, "none").exceeded


@given(
    specs=finding_specs,
    threshold=st.sampled_from(THRESHOLDS),
    extra=severities,
    status=st.sampled_from([status for status in FindingStatus if status not in COUNTED]),
)
def test_a_non_counted_finding_never_changes_the_result(
    specs: list[tuple[Severity, FindingStatus]],
    threshold: Threshold,
    extra: Severity,
    status: FindingStatus,
) -> None:
    findings = [finding(severity, state) for severity, state in specs]
    before = evaluate_threshold(findings, threshold)
    after = evaluate_threshold([*findings, finding(extra, status)], threshold)
    assert (after.exceeded, after.counted_at_or_above, after.worst) == (
        before.exceeded,
        before.counted_at_or_above,
        before.worst,
    )
    assert after.not_counted == before.not_counted + 1


# final_exit_code


@pytest.mark.parametrize("exceeded", [False, True])
@pytest.mark.parametrize("blocked", [0, 1])
@pytest.mark.parametrize("degraded", [(), ("analyse-rules",)])
@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("strict_privacy", [False, True])
def test_final_exit_code_truth_table(
    exceeded: bool, blocked: int, degraded: tuple[str, ...], strict: bool, strict_privacy: bool
) -> None:
    threshold = ThresholdResult(exceeded, Severity.HIGH, 1 if exceeded else 0, None)
    outcome = cli_result(degraded=degraded, blocked=blocked)
    code = final_exit_code(outcome, threshold, strict=strict, strict_privacy=strict_privacy)
    if strict and degraded:
        expected = ExitCode.INTERNAL
    elif strict_privacy and blocked:
        expected = ExitCode.PRIVACY_BLOCK
    elif exceeded:
        expected = ExitCode.FINDINGS
    else:
        expected = ExitCode.OK
    assert code is expected
    error = exit_error(code, outcome, threshold)
    assert (error is None) is (code is ExitCode.OK)
    if error is not None:
        assert error.exit_code == code


def test_exit_errors_carry_the_documented_codes() -> None:
    threshold = ThresholdResult(True, Severity.HIGH, 5, Severity.CRITICAL)
    outcome = cli_result(degraded=("analyse-rules",), blocked=2)
    codes = {code: getattr(exit_error(code, outcome, threshold), "code", None) for code in ExitCode}
    assert codes[ExitCode.INTERNAL] == "stage_degraded"
    assert codes[ExitCode.PRIVACY_BLOCK] == "egress_blocked"
    assert codes[ExitCode.FINDINGS] == "threshold_exceeded"
    assert codes[ExitCode.OK] is None


def test_threshold_lines() -> None:
    failing = ThresholdResult(True, Severity.HIGH, 5, Severity.CRITICAL, 2)
    assert threshold_lines(failing) == [
        "threshold: high; 5 finding(s) at or above it: failing (exit 1)",
        "2 finding(s) not counted (suppressed, accepted or false positive)",
    ]
    passing = ThresholdResult(False, Severity.CRITICAL, 0, Severity.HIGH)
    assert threshold_lines(passing) == ["threshold: critical; 0 finding(s) at or above it: passing"]
    assert threshold_lines(ThresholdResult(False, "none", 0, None)) == [
        "threshold: none; the severity gate is disabled"
    ]


# The scan command.


@pytest.fixture
def project(project_dir: Path) -> Path:
    (project_dir / ".git").mkdir()
    return project_dir


def run_scan_cli(
    cli: Cli,
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    findings: list[Finding],
    *args: str,
    **stub: Any,
) -> CliResult:
    install_stub(monkeypatch, findings=findings, state_dir=project / ".codekavach", **stub)
    return cli(["scan", str(project), *args])


HIGH_AND_LOW = [finding(Severity.HIGH), finding(Severity.LOW)]


@pytest.mark.parametrize(
    ("fail_on", "exit_code"), [("high", 1), ("critical", 0), ("none", 0), ("info", 1)]
)
def test_fail_on_values(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch, fail_on: str, exit_code: int
) -> None:
    human = run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW, "--fail-on", fail_on)
    assert human.exit_code == exit_code, human.stderr
    assert f"threshold: {fail_on}" in human.stdout
    assert ("failing (exit 1)" in human.stdout) is (exit_code == 1)
    machine = run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW, "--fail-on", fail_on, "--json")
    assert machine.exit_code == exit_code
    envelope = machine.json
    assert envelope["exit_code"] == exit_code
    assert envelope["ok"] is (exit_code == 0)
    threshold = envelope["data"]["threshold"]
    assert (threshold["fail_on"], threshold["exceeded"]) == (fail_on, exit_code == 1)
    assert envelope["data"]["scan_id"]  # the result is rendered before the exit code is decided


def test_counted_number_in_json(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW, "--fail-on", "low", "--json")
    assert result.json["data"]["threshold"] == {"fail_on": "low", "exceeded": True, "counted": 2}


def test_not_counted_findings_do_not_fail(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = [
        finding(Severity.CRITICAL, FindingStatus.SUPPRESSED),
        finding(Severity.HIGH, FindingStatus.FALSE_POSITIVE),
    ]
    result = run_scan_cli(cli, project, monkeypatch, findings, "--fail-on", "low")
    assert result.exit_code == 0, result.stderr
    assert "2 finding(s) not counted" in result.stdout
    assert "threshold: low; 0 finding(s) at or above it: passing" in result.stdout


def test_threshold_comes_from_settings(
    cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default = run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW)
    assert default.exit_code == 1
    assert "threshold: high; 1 finding(s) at or above it: failing (exit 1)" in default.stdout
    demo = run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW, "--profile", "demo")
    assert demo.exit_code == 0, demo.stderr
    assert "threshold: none" in demo.stdout
    (project / "codekavach.toml").write_text('[scan]\nfail_on = "critical"\n', encoding="utf-8")
    assert run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW).exit_code == 0


def test_strict_privacy(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    relaxed = run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW, blocked=1)
    assert relaxed.exit_code == 1
    assert "warning[egress_blocked]" in relaxed.stderr
    strict = run_scan_cli(cli, project, monkeypatch, HIGH_AND_LOW, "--strict-privacy", blocked=1)
    assert strict.exit_code == 3
    assert "error[egress_blocked]" in strict.stderr
    assert "threshold: high" in strict.stdout  # rendered before exiting
    machine = run_scan_cli(
        cli, project, monkeypatch, HIGH_AND_LOW, "--strict-privacy", "--json", blocked=1
    )
    assert (machine.exit_code, machine.json["exit_code"]) == (3, 3)
    assert machine.json["data"]["threshold"]["exceeded"] is True
    unblocked = run_scan_cli(cli, project, monkeypatch, [], "--strict-privacy")
    assert unblocked.exit_code == 0


def test_strict(cli: Cli, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    degraded = {"order": ("ingest", "analyse-rules"), "failed": ("analyse-rules",)}
    relaxed = run_scan_cli(cli, project, monkeypatch, [], **degraded)
    assert relaxed.exit_code == 0
    assert "warning[stage_degraded]" in relaxed.stderr
    strict = run_scan_cli(cli, project, monkeypatch, [], "--strict", **degraded)
    assert strict.exit_code == 4
    assert "error[stage_degraded]" in strict.stderr
    both = run_scan_cli(
        cli, project, monkeypatch, HIGH_AND_LOW, "--strict", "--strict-privacy", "--json",
        blocked=1, **degraded,
    )  # fmt: skip
    assert (both.exit_code, both.json["exit_code"]) == (4, 4)
