"""Correlation, suppressions, baselines and deltas of the aggregate stage (issue 240)."""

from datetime import date
from pathlib import Path

from codekavach.analysis.aggregate.baseline import load_baseline, write_baseline
from codekavach.analysis.aggregate.correlate import correlate
from codekavach.analysis.aggregate.delta import compute_delta
from codekavach.analysis.aggregate.suppress import (
    FileRule,
    apply_suppressions,
    load_file_rules,
)
from codekavach.core.models import Candidate, Confidence, Location, Severity
from codekavach.core.models.enums import CandidateKind


def cand(  # noqa: PLR0917
    engine: str, rule: str, line: int, cwe: int = 89, fp: str = "a", path: str = "a.py"
) -> Candidate:
    return Candidate.create(
        rule_id=rule,
        engine=engine,
        cwe=(cwe,),
        locations=(Location(path=path, start_line=line, end_line=line),),
        engine_severity=Severity.HIGH,
        engine_confidence=Confidence.MEDIUM,
        fingerprint="ckfp1:" + fp * 32,
    )


def test_two_engines_on_one_weakness_become_one_with_higher_confidence() -> None:
    merged = correlate([cand("opengrep", "r1", 11, fp="b"), cand("codekavach-rules", "r2", 10)])
    assert len(merged) == 1
    kept = merged[0]
    assert kept.engine == "codekavach-rules"
    assert kept.engine_confidence is Confidence.HIGH
    assert "opengrep:r1" in dict(kept.properties)["aggregate.also_reported_by"]


def test_different_cwe_or_distant_lines_stay_separate() -> None:
    items = [cand("e1", "r", 10), cand("e2", "r", 10, cwe=79, fp="b"), cand("e3", "r", 40, fp="c")]
    assert len(correlate(items)) == 3


def test_secrets_are_not_folded_into_code_findings() -> None:
    secret = cand("codekavach-secrets", "secret.x", 10, cwe=798, fp="d").evolve(
        kind=CandidateKind.SECRET
    )
    assert len(correlate([secret, cand("codekavach-rules", "r", 10, cwe=798, fp="e")])) == 2


def test_inline_suppression_needs_a_justification(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "x = 1\n"
        "# codekavach:ignore[r1] -- value is a constant from our own table\n"
        "y = query(x)\n"
        "z = query(x)  # codekavach:ignore[r1]\n"
    )
    justified = cand("e", "r1", 3, fp="a")
    bare = cand("e", "r1", 4, fp="b")
    kept, applied, unjustified = apply_suppressions([justified, bare], tmp_path, [])
    assert kept == [bare]
    assert applied[0].justification.startswith("value is a constant")
    assert unjustified == [("a.py", 4)]


def test_inline_suppression_for_another_rule_does_not_apply(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("y = q(x)  # codekavach:ignore[other] -- reason here\n")
    kept, applied, _ = apply_suppressions([cand("e", "r1", 1)], tmp_path, [])
    assert len(kept) == 1
    assert not applied


def test_file_rules_match_rule_cwe_and_glob(tmp_path: Path) -> None:
    rules = [FileRule("CWE-89", "deploy/**", "accepted by the risk board")]
    inside = cand("e", "r", 1, path="deploy/x.py")
    outside = cand("e", "r", 1, fp="b", path="src/x.py")
    kept, applied, _ = apply_suppressions([inside, outside], tmp_path, rules)
    assert kept == [outside]
    assert applied[0].source == "file"


def test_suppressions_file_drops_entries_without_justification_or_expired(tmp_path: Path) -> None:
    path = tmp_path / "s.yaml"
    path.write_text(
        "suppressions:\n"
        "  - {rule: a, path: '**', justification: ok}\n"
        "  - {rule: b, path: '**'}\n"
        "  - {rule: c, path: '**', justification: old, expires: 2020-01-01}\n"
    )
    assert [r.rule for r in load_file_rules(path, today=date(2026, 1, 1))] == ["a"]


def test_baseline_round_trip_and_delta(tmp_path: Path) -> None:
    items = [cand("e", "r", 1, fp="a"), cand("e", "r", 2, fp="b")]
    path = tmp_path / ".codekavach" / "baseline.json"
    assert write_baseline(path, items) == 2
    known = load_baseline(path)
    assert set(known) == {i.fingerprint for i in items}
    delta = compute_delta(known, [items[1].fingerprint, "ckfp1:" + "c" * 32])
    assert delta.as_dict() == {"new": 1, "fixed": 1, "unchanged": 1}
