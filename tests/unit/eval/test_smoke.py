"""CI smoke evaluation on KavachBank with the mock provider (#280)."""

import json
from pathlib import Path

from codekavach.eval.detection import run_detection
from codekavach.eval.leakage import run_leakage


def test_detection_smoke(tmp_path: Path) -> None:
    results = run_detection("kavachbank", ["L2"], ["mock"], str(tmp_path), None)
    arms = {a["arm"]: a for a in results["arms"]}
    engines = arms["engines-only"]["overall"]
    assert engines["recall"] >= 0.8, "the engines must find most planted vulnerabilities"
    assert engines["f1_ci"][0] <= engines["f1"] <= engines["f1_ci"][1]
    assert arms["llm-raw"]["skipped_reason"]
    for name in ("results.json", "summary.md", "table.tex", "f1.svg"):
        assert (tmp_path / name).is_file()
    assert json.loads((tmp_path / "results.json").read_text())["kind"] == "detection"


def test_leakage_smoke_zero_leak(tmp_path: Path) -> None:
    results = run_leakage(None, "kavachbank", ["L2", "L4"], [], str(tmp_path), ablations=False)
    assert results["zero_leak"], "no canary may reach a payload at L2 or above"
    assert (
        results["levels"]["L4"]["payloads_sent"] == 0
        or results["levels"]["L4"]["leakage_score"] < 5
    )
    assert results["levels"]["L2"]["canary"]["by_category"]["secret"]["checked"] > 0
    text = (tmp_path / "results.json").read_text()
    assert "zebraquartz" not in text and "hunter2hunter2" not in text
