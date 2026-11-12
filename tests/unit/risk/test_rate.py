"""Severity mapping and the rate stage (E13-03)."""

from pathlib import Path

import pytest

from codekavach.core.models.candidate import Candidate
from codekavach.core.models.enums import Confidence, FindingStatus, Severity
from codekavach.core.models.finding import Finding
from codekavach.core.models.summary import ScanSummary
from codekavach.core.pipeline import keys
from codekavach.core.pipeline.stage import FailurePolicy, StageCategory, describe_stage
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.privacy.restore.models import RestoredVerdict
from codekavach.risk.severity import map_severity
from codekavach.risk.stage import RateStage
from tests.support.factories import (
    CANDIDATE_ID,
    SAMPLE_LINE,
    SAMPLE_PATH,
    make_candidate,
)
from tests.support.pipeline import make_run_context

# --- map_severity: one test per branch --------------------------------------------------------


def test_a_cvss_score_decides_before_anything_else() -> None:
    candidate = make_candidate(
        engine_severity=Severity.LOW, cwe=(89,), properties=(("cvss4_score", "9.3"),)
    )
    assert map_severity(candidate, None) is Severity.CRITICAL


@pytest.mark.parametrize("value", ["not-a-number", "11.0", "-1", "nan"])
def test_an_unusable_score_is_ignored(value: str) -> None:
    candidate = make_candidate(engine_severity=Severity.LOW, properties=(("cvss4_score", value),))
    assert map_severity(candidate, None) is Severity.LOW


def test_the_engine_severity_decides_without_a_score() -> None:
    assert map_severity(make_candidate(engine_severity=Severity.INFO), None) is Severity.INFO


def test_the_cwe_family_decides_without_a_score_or_an_engine_severity() -> None:
    candidate = make_candidate(engine_severity=None, cwe=(89,))
    assert map_severity(candidate, None) is Severity.HIGH
    assert map_severity(candidate.evolve(cwe=(209,)), None) is Severity.LOW


def test_an_unknown_cwe_falls_back_to_medium() -> None:
    candidate = make_candidate(engine_severity=None, cwe=(9999,))
    assert map_severity(candidate, None) is Severity.MEDIUM
    assert map_severity(candidate.evolve(cwe=()), None) is Severity.MEDIUM


# --- the stage --------------------------------------------------------------------------------


def declared() -> None:
    info = describe_stage(RateStage())
    assert info.name == "rate"
    assert set(info.requires) == {keys.CANDIDATES}
    assert keys.VERDICTS_RESTORED in info.optional_requires
    assert set(info.provides) == {keys.FINDINGS, keys.SCAN_SUMMARY}
    assert info.category is StageCategory.RATE


def test_the_stage_declares_the_documented_keys_and_degrades() -> None:
    declared()
    assert describe_stage(RateStage()).failure_policy is FailurePolicy.DEGRADE


def verdict(vulnerable: bool | None, **fields: object) -> RestoredVerdict:
    return RestoredVerdict(
        candidate_id=CANDIDATE_ID,
        verdict_dropped=False,
        is_vulnerable=vulnerable,
        confidence=Confidence.HIGH,
        reasoning="The query is built from user input.",
        impact="An attacker reads other customers' rows.",
        remediation="Use a parameterised query.",
        **fields,  # type: ignore[arg-type]
    )


def rate(
    tmp_path: Path,
    candidates: list[Candidate],
    verdicts: list[RestoredVerdict] | None = None,
) -> tuple[list[Finding], ScanSummary, InMemoryArtefactStore]:
    source = tmp_path / SAMPLE_PATH
    source.parent.mkdir(parents=True)
    source.write_text(
        "".join(f"line_{number} = {number}\n" for number in range(1, SAMPLE_LINE + 10)),
        encoding="utf-8",
    )
    store = InMemoryArtefactStore()
    store.put(keys.CANDIDATES, candidates)
    if verdicts is not None:
        store.put(keys.VERDICTS_RESTORED, verdicts)
    ctx = make_run_context(store=store, project_root=tmp_path).for_stage("rate")
    RateStage().run(ctx)
    return (
        store.get_list(keys.FINDINGS, Finding),
        store.get(keys.SCAN_SUMMARY, ScanSummary),
        store,
    )


def test_without_restored_verdicts_every_candidate_still_becomes_a_finding(tmp_path: Path) -> None:
    findings, summary, _ = rate(tmp_path, [make_candidate()])
    assert len(findings) == 1 and summary.findings_total == 1
    # SQL injection on an unauthenticated path: the family's CVSS v4.0 vector scores critical.
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].cvss4_score is not None and findings[0].cvss4_score >= 9.0
    assert findings[0].provenance.llm_reviews == ()
    assert summary.candidates_reviewed_by_llm == 0


def test_a_dismissing_verdict_keeps_the_finding_open_and_records_the_reasoning(
    tmp_path: Path,
) -> None:
    findings, summary, _ = rate(tmp_path, [make_candidate()], [verdict(False)])
    (finding,) = findings
    assert finding.status is FindingStatus.OPEN
    assert finding.severity is Severity.CRITICAL  # the model never moves the severity by default
    assert finding.confidence is Confidence.LOW
    assert finding.remediation == "Use a parameterised query."
    assert summary.findings_total == 1 and summary.candidates_reviewed_by_llm == 1


def test_a_dropped_verdict_adds_no_model_text(tmp_path: Path) -> None:
    dropped = RestoredVerdict(
        candidate_id=CANDIDATE_ID,
        verdict_dropped=True,
        is_vulnerable=None,
        confidence=Confidence.LOW,
    )
    findings, summary, _ = rate(tmp_path, [make_candidate()], [dropped])
    (finding,) = findings
    assert finding.remediation.startswith("Use parameterised queries")  # knowledge base default
    assert "attacker" not in finding.impact.narrative
    assert finding.impact.narrative.startswith("CVSS v4.0")
    assert summary.candidates_reviewed_by_llm == 0


def test_the_snippet_is_cut_from_the_original_file_at_the_real_line(tmp_path: Path) -> None:
    (finding,), _, _ = rate(tmp_path, [make_candidate()])
    (evidence,) = finding.evidence
    assert evidence.location.start_line == SAMPLE_LINE
    text = evidence.render_text()
    assert f"line_{SAMPLE_LINE} = {SAMPLE_LINE}" in text
    assert "var_" not in text and "fn_" not in text


def test_a_candidate_whose_file_is_missing_still_becomes_a_finding_without_evidence(
    tmp_path: Path,
) -> None:
    store = InMemoryArtefactStore()
    store.put(keys.CANDIDATES, [make_candidate()])
    ctx = make_run_context(store=store, project_root=tmp_path).for_stage("rate")
    RateStage().run(ctx)
    (finding,) = store.get_list(keys.FINDINGS, Finding)
    assert finding.evidence == ()
