"""OWASP risk rating, matrix, severity policy, context heuristics and the rated finding."""

from pathlib import Path

import pytest

from codekavach.core.models.enums import CandidateKind, Confidence, Severity
from codekavach.core.models.finding import Finding
from codekavach.core.pipeline import keys
from codekavach.core.store.memory import InMemoryArtefactStore
from codekavach.risk.context import RatingContext
from codekavach.risk.cvss.v4 import Cvss4Vector
from codekavach.risk.matrix import MATRIX_SEVERITY, impact_level, likelihood_level
from codekavach.risk.owasp import OVERALL, band, rate_owasp, technical_impact_from
from codekavach.risk.rating import RatingEngine
from codekavach.risk.severity import (
    DEFAULT_POLICY,
    SeverityBand,
    SeverityPolicy,
    load_policy,
    map_severity,
    step_down,
)
from codekavach.risk.stage import RateStage
from codekavach.risk.taxonomy.loader import default_data_dir, parse_knowledge_base
from codekavach.risk.taxonomy.mapper import StandardsAnnotator
from codekavach.risk.templates import base_vectors_for
from tests.support.factories import SAMPLE_LINE, SAMPLE_PATH, make_candidate
from tests.support.pipeline import make_run_context

KB = parse_knowledge_base(default_data_dir())


# --- OWASP risk rating and the matrix ---------------------------------------------------------


def test_owasp_bands_and_overall_table_follow_the_methodology() -> None:
    assert (band(2.9), band(3.0), band(5.99), band(6.0)) == ("low", "medium", "medium", "high")
    assert OVERALL[("high", "high")] == "critical"
    assert OVERALL[("low", "low")] == "note"
    assert OVERALL[("medium", "high")] == "high"
    assert len(OVERALL) == 9


def test_technical_impact_maps_cvss_consequences() -> None:
    full = Cvss4Vector.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    factors = technical_impact_from(full)
    assert factors.loss_of_confidentiality == 9 and factors.loss_of_accountability == 9
    xss = Cvss4Vector.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N")
    factors = technical_impact_from(xss)
    assert factors.loss_of_confidentiality == 6 and factors.loss_of_accountability == 7


def test_context_moves_owasp_likelihood() -> None:
    family = KB.families["sql-injection"]
    cvss = Cvss4Vector.parse(family.cvss4)
    open_ = rate_owasp(RatingContext(entry_point="network"), cvss=cvss, threat=family.threat)
    guarded = rate_owasp(
        RatingContext(entry_point="network", authentication_required=True),
        cvss=cvss,
        threat=family.threat,
    )
    local = rate_owasp(RatingContext(entry_point="local"), cvss=cvss, threat=family.threat)
    assert open_.likelihood_score > guarded.likelihood_score > local.likelihood_score
    assert open_.overall in ("high", "critical")


def test_matrix_levels_and_labels() -> None:
    assert [impact_level(s) for s in (0.0, 3.9, 4.0, 8.9, 9.0)] == [1, 2, 3, 4, 5]
    assert likelihood_level(9.0, Confidence.HIGH) == 5
    assert likelihood_level(9.0, Confidence.LOW) == 4
    assert likelihood_level(0.0, Confidence.MEDIUM) == 1
    assert len(MATRIX_SEVERITY) == 25
    assert MATRIX_SEVERITY[(5, 5)] == "critical" and MATRIX_SEVERITY[(1, 1)] == "low"
    assert MATRIX_SEVERITY[(3, 3)] == "medium" and MATRIX_SEVERITY[(4, 4)] == "high"


# --- CVSS templates and context -----------------------------------------------------------------


def test_templates_adjust_vectors_with_evidence() -> None:
    family = KB.families["sql-injection"]
    v4, v31, rationale, adjustments = base_vectors_for(
        RatingContext(entry_point="local", authentication_required=True), family
    )
    assert v4.get("AV") == "L" and v4.get("PR") == "L"
    assert v31.as_dict["AV"] == "L" and v31.as_dict["PR"] == "L"
    assert {"local_entry_point", "authentication_required"} <= set(adjustments)
    assert dict(rationale)["AV"].startswith("untrusted data enters from a local")
    default4, *_ = base_vectors_for(RatingContext(), family)
    assert v4.score() < default4.score()


def test_engine_vector_wins_over_the_template() -> None:
    vector = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
    v4, *_ = base_vectors_for(RatingContext(cvss4_vector=vector), KB.families["xss"])
    assert v4.to_string() == vector


def test_context_reads_entry_point_and_auth_guard() -> None:
    lines = {
        1: "from flask import request",
        2: "@app.route('/a')",
        3: "@login_required",
        4: "def handler():",
        5: "    q = request.args['q']",
        6: "    cursor.execute('select ' + q)",
    }
    text = "\n".join(lines[i] for i in sorted(lines))
    candidate = make_candidate()
    context = RatingContext.for_candidate(
        candidate,
        read_line=lambda _path, line: lines.get(line),
        file_text=lambda _path: "\n" * (SAMPLE_LINE - 7) + text + "\n" * 5,
    )
    assert context.entry_point == "network"
    assert context.authentication_required is True
    assert context.has_taint_path and not context.is_test_code
    test_context = RatingContext.for_candidate(
        candidate.evolve(
            locations=(candidate.locations[0].model_copy(update={"path": "tests/test_x.py"}),),
            taint_path=None,
        )
    )
    assert test_context.is_test_code


# --- severity policy ---------------------------------------------------------------------------


def test_policy_bands_downgrades_and_model_opt_in(tmp_path: Path) -> None:
    engine = RatingEngine(KB)
    production = engine.rate(RatingContext(cwe=(89,)), confidence=Confidence.HIGH)
    in_tests = engine.rate(RatingContext(cwe=(89,), is_test_code=True), confidence=Confidence.HIGH)
    assert production.severity is Severity.CRITICAL
    assert "policy:test_code_downgrade" in in_tests.adjustments
    dismissed = engine.rate(
        RatingContext(cwe=(89,)),
        confidence=Confidence.LOW,
        model_is_vulnerable=False,
        model_confidence=Confidence.HIGH,
    )
    assert dismissed.severity is Severity.CRITICAL  # default: the model does not move severity
    opt_in = RatingEngine(KB, policy=SeverityPolicy(model_downgrade=True)).rate(
        RatingContext(cwe=(89,)),
        confidence=Confidence.LOW,
        model_is_vulnerable=False,
        model_confidence=Confidence.HIGH,
    )
    assert opt_in.severity is step_down(Severity.CRITICAL)
    assert "policy:model_downgrade" in opt_in.adjustments
    strict = SeverityPolicy(
        bands=(
            SeverityBand(severity=Severity.CRITICAL, min_score=9.5),
            SeverityBand(severity=Severity.HIGH, min_score=6.0),
            SeverityBand(severity=Severity.INFO, min_score=0.0),
        )
    )
    assert strict.from_score(9.3) is Severity.HIGH
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("severity:\n  source: strictest\n  engine_floor: true\n")
    loaded = load_policy(policy_file)
    assert loaded.source == "strictest" and loaded.engine_floor
    policy_file.write_text("severity: [broken")
    assert load_policy(policy_file) is DEFAULT_POLICY
    with pytest.raises(ValueError, match=r"0\.0"):
        SeverityPolicy(bands=(SeverityBand(severity=Severity.HIGH, min_score=7.0),))


def test_map_severity_keeps_its_contract_with_a_rating() -> None:
    rating = RatingEngine(KB).rate(RatingContext(cwe=(79,)), confidence=Confidence.MEDIUM)
    assert map_severity(make_candidate(), None, rating=rating) is rating.severity


def test_rating_runs_without_a_knowledge_base() -> None:
    result = RatingEngine(None).rate(RatingContext(cwe=(89,)), confidence=Confidence.MEDIUM)
    assert result.cvss4_score > 0 and result.family is None
    assert result.to_risk().family is None


# --- the annotator and the rated finding --------------------------------------------------------


def test_annotator_fills_standards_and_compliance() -> None:
    notes = StandardsAnnotator(KB).annotations((89,))
    assert notes.owasp[0].id == "A03:2021" and notes.owasp[0].basis == "official"
    schemes = {ref.scheme for ref in notes.taxonomy}
    assert {"owasp-asvs", "capec", "cwe-top25"} <= schemes
    frameworks = {ref.scheme for ref in notes.compliance}
    assert {"pci-dss", "iso27001", "nist-ssdf", "rbi", "sebi"} <= frameworks
    assert all(ref.basis == "derived" for ref in notes.compliance)
    assert any(ref.url and "cwe.mitre.org" in ref.url for ref in notes.references)
    assert notes.remediation


def test_a_weakness_with_its_own_advice_does_not_get_the_family_cheat_sheets() -> None:
    notes = StandardsAnnotator(KB).annotations((829,))  # pull_request_target, family integrity
    titles = " ".join(ref.title or "" for ref in notes.references)
    assert "pull_request_target" in notes.remediation
    assert "Mass Assignment" not in titles and "Prototype" not in titles
    assert "cwe.mitre.org" in " ".join(ref.url or "" for ref in notes.references)


def test_the_stage_populates_every_rating_field(tmp_path: Path) -> None:
    source = tmp_path / SAMPLE_PATH
    source.parent.mkdir(parents=True)
    source.write_text("x = 1\n" * (SAMPLE_LINE + 10), encoding="utf-8")
    store = InMemoryArtefactStore()
    store.put(keys.CANDIDATES, [make_candidate()])
    RateStage().run(make_run_context(store=store, project_root=tmp_path).for_stage("rate"))
    (finding,) = store.get_list(keys.FINDINGS, Finding)
    assert finding.cvss4_vector and finding.cvss4_vector.startswith("CVSS:4.0/")
    assert finding.cvss31_vector and finding.cvss31_score is not None
    assert Cvss4Vector.parse(finding.cvss4_vector).score() == finding.cvss4_score
    assert finding.owasp and finding.compliance and finding.taxonomy and finding.references
    assert finding.remediation
    assert finding.risk is not None and finding.risk.family == "sql-injection"
    assert finding.risk.cvss4_nomenclature == "CVSS-B"
    assert 1 <= finding.likelihood.level <= 5 and finding.impact.level == 5
    assert finding.likelihood.rationale


def test_engine_rated_kinds_keep_the_engine_severity_and_a_matching_vector() -> None:
    engine = RatingEngine(KB)
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        result = engine.rate(
            RatingContext(
                cwe=(250,), kind=CandidateKind.MISCONFIGURATION, engine_severity=severity
            ),
            confidence=Confidence.HIGH,
        )
        assert result.severity is severity
        assert DEFAULT_POLICY.from_score(result.cvss4_score) is severity
        assert DEFAULT_POLICY.from_score(result.cvss31_score) is severity
        assert result.to_risk().severity_source == "engine"
    # A hotspot (Bandit's "import subprocess") keeps its rule's rating, not the worst case of
    # its weakness family (command injection would be critical).
    hotspot = engine.rate(
        RatingContext(cwe=(78,), kind=CandidateKind.HOTSPOT, engine_severity=Severity.LOW),
        confidence=Confidence.HIGH,
    )
    assert hotspot.severity is Severity.LOW
    kev = engine.rate(
        RatingContext(
            cwe=(1395,), kind=CandidateKind.DEPENDENCY, engine_severity=Severity.HIGH, kev=True
        ),
        confidence=Confidence.HIGH,
    )
    assert kev.cvss4.get("E") == "A" and kev.nomenclature == "CVSS-BT"
