import re
from pathlib import Path

import pytest

from tests.support.cli import run_cli
from tests.support.golden import assert_matches_golden
from tests.support.scan_stub import install_stub

GOLDEN = Path(__file__).parent / "golden" / "scan_summary.txt"
KAVACHBANK = Path(__file__).resolve().parents[3] / "fixtures" / "kavachbank"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    return root


def test_human_summary_golden(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub(monkeypatch)
    result = run_cli(["scan", str(project)], home=project.parent / "home")
    assert result.exit_code == 0, result.stderr
    assert_matches_golden(result.stdout, GOLDEN)


def test_json_data(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_stub(monkeypatch)
    result = run_cli(["scan", str(project), "--json"], home=project.parent / "home")
    data = result.json["data"]
    assert set(data) == {
        "scan_id", "target", "privacy_level", "provider", "summary", "egress",
        "degraded_stages", "report_files", "state_dir",
    }  # fmt: skip
    assert data["provider"] == {"id": "mock", "kind": "mock", "remote": False, "model": None}
    assert set(data["summary"]["by_severity"]) == {"critical", "high", "medium", "low", "info"}
    assert data["summary"]["findings_total"] == sum(data["summary"]["by_severity"].values())
    assert "findings" not in data
    assert re.fullmatch(r"scan_[0-9A-Z]{26}", data["scan_id"])


@pytest.mark.skipif(
    not (KAVACHBANK / "codekavach.toml").exists(),
    reason="Demo 1 path: needs the kavachbank fixture and the M1 stages",
)
def test_demo_scan_without_api_key() -> None:
    result = run_cli(["scan", str(KAVACHBANK), "--profile", "demo"])
    assert result.exit_code == 0, result.stderr
