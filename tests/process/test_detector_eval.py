"""Unit tests of ``tools/detector_eval.py``: matching, metrics, the gate and the report (E08-04)."""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from codekavach.core.models import Confidence, Language, PlaceholderKind
from codekavach.privacy.detect.base import TypedSpan

REPO = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("detector_eval", REPO / "tools/detector_eval.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["detector_eval"] = module
    spec.loader.exec_module(module)
    return module


tool = _load()


def span(subtype: str, start: int, end: int, confidence: Confidence = Confidence.HIGH) -> TypedSpan:
    return TypedSpan(
        kind=PlaceholderKind.PII,
        subtype=subtype,
        start_byte=start,
        end_byte=end,
        confidence=confidence,
        detector="fake",
    )


def label(subtype: str, start: int, end: int, confidence: str = "high") -> Any:
    return tool.Label(subtype, confidence, start, end)


def test_jaccard_of_half_open_ranges() -> None:
    assert tool.jaccard((0, 10), (0, 10)) == 1.0
    assert tool.jaccard((0, 10), (5, 15)) == pytest.approx(5 / 15)
    assert tool.jaccard((0, 10), (10, 20)) == 0.0
    assert tool.jaccard((3, 3), (3, 3)) == 0.0


def test_matching_is_one_to_one_and_takes_the_best_overlap_first() -> None:
    matches = tool.match([(0, 10), (2, 10)], [(2, 10)])
    assert [(p, lab) for p, lab, _ in matches] == [(1, 0)]


def test_a_hand_computed_example() -> None:
    """Labels: email 0-10, email 20-30, iban 40-50. Predictions: email 0-10, email 21-30 (Jaccard
    0.9), email 60-70 (false positive), iban 41-50 (0.9), ipv4_row 80-90 (false positive)."""
    counts: dict[str, Any] = {}
    tool.score_case(
        counts,
        [
            span("email", 0, 10),
            span("email", 21, 30),
            span("email", 60, 70),
            span("iban", 41, 50),
            span("ipv4", 80, 90),
        ],
        [
            label("email", 0, 10),
            label("email", 20, 30),
            label("iban", 40, 50),
            label("iban", 90, 99),
        ],
    )
    email, iban, ipv4_row = counts["email"], counts["iban"], counts["ipv4"]
    assert (email.tp, email.fp, email.fn) == (2, 1, 0)
    assert email.precision() == pytest.approx(2 / 3) and email.recall() == 1.0
    assert email.f1() == pytest.approx(0.8)
    assert email.jaccard() == pytest.approx((1.0 + 0.9) / 2)
    assert (iban.tp, iban.fp, iban.fn) == (1, 0, 1)
    assert iban.precision() == 1.0 and iban.recall() == 0.5
    assert iban.f1() == pytest.approx(2 / 3)
    assert (ipv4_row.tp, ipv4_row.fp, ipv4_row.fn) == (0, 1, 0)
    assert ipv4_row.precision() == 0.0 and ipv4_row.recall() is None and ipv4_row.f1() is None


def test_a_label_of_another_subtype_never_matches() -> None:
    counts: dict[str, Any] = {}
    tool.score_case(counts, [span("email", 0, 10)], [label("iban", 0, 10)])
    assert (counts["email"].fp, counts["iban"].fn) == (1, 1)


def test_a_detector_is_scored_only_on_the_subtypes_it_reported() -> None:
    counts: dict[str, Any] = {}
    tool.score_case(
        counts,
        [span("email", 0, 10)],
        [label("email", 0, 10), label("iban", 20, 30)],
        subtypes={"email"},
    )
    assert set(counts) == {"email"}


def test_high_confidence_labels_are_counted_for_the_gate() -> None:
    counts: dict[str, Any] = {}
    tool.score_case(
        counts,
        [span("email", 0, 10)],
        [label("email", 0, 10), label("email", 20, 30), label("email", 40, 50, "low")],
    )
    assert (counts["email"].high_labels, counts["email"].high_found) == (2, 1)


def test_the_gate_names_the_subtype_whose_high_confidence_label_is_missed() -> None:
    report = tool.Report("labelled", 1, 1, 2)
    report.rows[tool.UNION] = {
        "good": tool.Counts(tp=2, high_labels=2, high_found=2),
        "bad": tool.Counts(tp=1, fn=1, high_labels=2, high_found=1),
        "low_only": tool.Counts(fn=1),
    }
    assert tool.failing_subtypes(report) == ["bad"]


class Fake:
    id = "fake.one"

    def detect(self, text: object, *, path: str, language: Language) -> list[TypedSpan]:
        return [span("email", 0, 5)]


def test_evaluate_scores_each_detector_and_the_union_and_reports_corpus_size() -> None:
    cases = [
        tool.Case(
            "c", "a", "hello world", "a.py", Language.PYTHON, (tool.Label("email", "high", 0, 5),)
        ),
        tool.Case("c", "b", "hello world", "b.py", Language.PYTHON, ()),
    ]
    (report,) = tool.evaluate(cases, [Fake()])
    assert (report.cases, report.unique_texts, report.labels) == (2, 1, 1)
    assert (report.rows[tool.UNION]["email"].tp, report.rows[tool.UNION]["email"].fp) == (1, 1)
    assert report.rows["fake.one"]["email"].tp == 1
    assert "repeats" in tool.render_markdown([report], "2026-01-01")


def test_the_reports_hold_counts_and_ratios_and_no_text() -> None:
    cases = [
        tool.Case(
            "c",
            "a",
            "SECRET-TEXT-123",
            "a.py",
            Language.PYTHON,
            (tool.Label("email", "high", 0, 5),),
        )
    ]
    reports = tool.evaluate(cases, [Fake()])
    markdown = tool.render_markdown(reports, "2026-01-01")
    document = json.loads(tool.render_json(reports, "2026-01-01"))
    assert "SECRET-TEXT" not in markdown + json.dumps(document)
    row = document["corpora"][0]["rows"][0]
    assert {"detector", "subtype", "tp", "fp", "fn", "precision", "recall", "f1", "jaccard"} <= set(
        row
    )
    assert "| union | email | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |" in markdown


def test_the_in_repository_corpus_meets_the_gate_and_the_cli_writes_both_files(
    tmp_path: Path,
) -> None:
    assert tool.main(["--check", "--out-dir", str(tmp_path), "--date", "2026-01-01"]) == 0
    assert (tmp_path / "report.md").read_text(encoding="utf-8").startswith("# Detector evaluation")
    document = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    (corpus,) = document["corpora"]
    assert corpus["corpus"] == "labelled" and corpus["labels"] > 50
    unions = [r for r in corpus["rows"] if r["detector"] == "union"]
    assert unions and all(r["recall"] in (None, 1.0) for r in unions)


def test_an_external_corpus_is_loaded_from_cases_jsonl(tmp_path: Path) -> None:
    row = {
        "path": "x.py",
        "language": "python",
        "text": "hello",
        "labels": [{"subtype": "email", "confidence": "high", "start_byte": 0, "end_byte": 5}],
    }
    (tmp_path / "cases.jsonl").write_text(json.dumps(row) + "\n\n", encoding="utf-8")
    (case,) = tool.external_cases("public", tmp_path)
    assert (case.corpus, case.language, case.labels[0].end) == ("public", Language.PYTHON, 5)


def test_a_reserved_or_malformed_external_argument_is_refused(tmp_path: Path) -> None:
    assert tool.main(["--out-dir", str(tmp_path), "--external", "labelled=x"]) == 2
    assert tool.main(["--out-dir", str(tmp_path), "--external", "nodir"]) == 2
