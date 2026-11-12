"""Unit tests of the evaluation harness pieces that need no scan (#278-#283)."""

import json
from pathlib import Path

import pytest

from codekavach.eval.datasets import Canary, DatasetError, TruthItem, load_dataset, resolve_dataset
from codekavach.eval.export import bar_chart_svg, detection_latex, detection_markdown
from codekavach.eval.leakage import (
    canary_exposure,
    identifier_recovery,
    leakage_score,
    sector_inference,
    slice_stitching,
)
from codekavach.eval.matcher import Reported, family, match
from codekavach.eval.metrics import score
from codekavach.eval.scanrun import PayloadView

TRUTH = [
    TruthItem("V1", 89, "a.py", 10),
    TruthItem("V2", 79, "b.js", 5),
    TruthItem("S1", 0, "a.py", 20, "safe"),
]


def rep(id_: str, file: str, line: int, *cwes: int) -> Reported:
    return Reported(id_, file, line, line, cwes)


def test_family_groups_related_cwes() -> None:
    assert family(327) == family(329)
    assert family(89) != family(79)
    assert family(99999) == "cwe-99999"


def test_matcher_counts_tp_fp_fn_and_scopes() -> None:
    result = match(
        TRUTH,
        [
            rep("f1", "a.py", 12, 89),  # within the window: TP
            rep("f1b", "a.py", 11, 89),  # second finding on the same label: duplicate
            rep("f2", "a.py", 20, 89),  # on the safe control: FP
            rep("f3", "b.js", 90, 79),  # right family, wrong place: FP
            rep("f4", "c.py", 1, 1395),  # dependency advisory CWE, out of scope
            rep("f5", "requirements.txt", 2, 89),  # manifest: out of scope
        ],
    )
    assert [m[0].id for m in result.matched] == ["V1"]
    assert [m.id for m in result.missed] == ["V2"]
    assert len(result.false_positives) == 2
    assert result.duplicates == 1
    assert result.out_of_scope == 2
    assert len(result.on_controls) == 1


def test_file_level_label_matches_any_line() -> None:
    result = match([TruthItem("J1", 89, "x.java", 0)], [rep("f", "x.java", 400, 564)])
    assert len(result.matched) == 1


def test_bootstrap_is_reproducible_and_bounded() -> None:
    a = score(8, 2, 2)
    b = score(8, 2, 2)
    assert a == b
    assert a.precision == 0.8 and a.recall == 0.8
    assert a.f1_ci[0] <= a.f1 <= a.f1_ci[1]
    assert score(0, 0, 0).f1 == 0.0


def test_kavachbank_adapter_reads_labels_and_canaries() -> None:
    ds = resolve_dataset("kavachbank")
    assert len(ds.vulnerabilities) == 10
    assert len(ds.controls) == 10
    kinds = {c.category for c in ds.canaries}
    assert {"secret", "term", "pii"} <= kinds
    assert ds.synthetic


def test_generic_json_layout(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "ground-truth.json").write_text(
        json.dumps(
            {
                "name": "toy",
                "synthetic": True,
                "vulnerabilities": [{"id": "T1", "cwe": 78, "file": "app.py", "line": 1}],
                "terms": ["secretword"],
            }
        )
    )
    ds = load_dataset(tmp_path)
    assert ds.name == "toy" and len(ds.vulnerabilities) == 1
    assert ds.canaries[0].value == "secretword"
    with pytest.raises(DatasetError):
        load_dataset(tmp_path / "missing")


def test_owasp_benchmark_and_juliet_layouts(tmp_path: Path) -> None:
    ob = tmp_path / "ob"
    (ob / "src").mkdir(parents=True)
    (ob / "src" / "BenchmarkTest00001.java").write_text("class A {}\n")
    (ob / "src" / "BenchmarkTest00002.java").write_text("class B {}\n")
    (ob / "expectedresults-1.2.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001, sqli, true, 89\nBenchmarkTest00002, sqli, false, 89\n"
    )
    ds = load_dataset(ob)
    assert ds.layout == "owasp-benchmark"
    assert len(ds.vulnerabilities) == 1 and len(ds.controls) == 1
    ju = tmp_path / "ju"
    ju.mkdir()
    (ju / "CWE89_SQL_Injection__Servlet_01.java").write_text("class A {}\n")
    assert load_dataset(ju).layout == "juliet"


def view(text: str, *segments: tuple[str, int, int], outcome: str = "sent") -> PayloadView:
    return PayloadView("cand", text, outcome, (), segments)


def test_canary_gate_and_l1_exemption() -> None:
    canaries = [
        Canary("hunter2hunter2", "secret"),
        Canary("zq_customer_ref", "identifier"),
        Canary("festival bonus", "term"),
    ]
    clean = [view("password = <SECRET_1>\nvar_1 = 2")]
    assert canary_exposure(clean, canaries)["passed"]
    dirty = [view("def f(zq_customer_ref): pass  # Festival Bonus")]
    l2 = canary_exposure(dirty, canaries, "L2")
    assert not l2["passed"] and l2["business_term_occurrences"] == 1
    assert canary_exposure(dirty, canaries, "L1")["passed"]  # L1 keeps names by design
    leaked = canary_exposure([view("hunter2hunter2")], canaries)
    assert not leaked["passed"]
    assert "hunter2hunter2" not in json.dumps(leaked)  # only hashes are reported


def test_identifier_recovery_and_stitching(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("def compute_festival_rate(account_balance):\n    return 1\n")
    seg = ("m.py", 1, 2)
    exposed = identifier_recovery(tmp_path, [view("def compute_festival_rate(x): ...", seg)], {})
    hidden = identifier_recovery(tmp_path, [view("def fn_1(param_1): ...", seg)], {})
    assert exposed["exact_rate"] > 0 and hidden["subword_rate"] == 0.0


def test_inference_and_score() -> None:
    banking = sector_inference([view("def loan_interest(account, balance, overdraft): ...")])
    assert banking["guess"] == "banking" and banking["evidence_share"] > 0
    blind = sector_inference([view("def fn_1(param_1): ...")])
    assert blind["evidence_share"] == 0
    report = {
        "canary": {"passed": True, "business_term_occurrences": 0},
        "identifier": {"subword_rate": 0.0},
        "inference": {"evidence_share": 0.0},
        "stitching": {"coverage": 0.0, "linkability": 0.0},
    }
    assert leakage_score(report) == 0.0
    report["canary"]["passed"] = False
    assert leakage_score(report) == 100.0


def test_stitching_links_shared_pseudonyms() -> None:
    ds = resolve_dataset("kavachbank")
    payloads = [view("a = fn_1(var_2)", ("services/api/db.py", 1, 5)), view("fn_1()")]
    result = slice_stitching(ds, payloads)
    assert result["linkable_pairs"] == 1 and result["covered_lines"] > 0


def test_exports_render() -> None:
    arm = {
        "arm": "engines-only", "findings": 3,
        "overall": score(2, 1, 0).to_dict(),
    }  # fmt: skip
    results = {
        "dataset": {"name": "toy", "layout": "x", "vulnerabilities": 2, "controls": 1,
                    "synthetic": True},
        "method": {"a": "b"},
        "arms": [arm, {"arm": "llm-raw", "skipped_reason": "never"}],
    }  # fmt: skip
    assert "engines-only" in detection_markdown(results)
    assert "\\begin{tabular}" in detection_latex(results)
    svg = bar_chart_svg(
        "t", ["a", "b"], {"F1": [0.5, 1.0]}, errors={"F1": [(0.4, 0.6), (0.9, 1.0)]}
    )
    assert svg.startswith("<svg") and svg.count("<rect") >= 3
