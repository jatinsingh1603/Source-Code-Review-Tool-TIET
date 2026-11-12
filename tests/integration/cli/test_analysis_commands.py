"""``baseline``, ``suppress``, ``secrets scan`` and ``diff`` (#236, #240)."""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from codekavach.integrations import store
from tests.support.cli import run_cli
from tests.support.golden import assert_matches_golden

GOLDEN = Path(__file__).parent / "golden"
# The vendor-documented example key; not a live credential.
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    return root


def _finding(fingerprint: str, path: str = "app.py", line: int = 3) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "title": f"Issue {fingerprint[-1]}",
        "severity": "high",
        "locations": [{"path": path, "start_line": line, "end_line": line}],
        "provenance": {"engines": [{"rule_id": "py.sql"}]},
    }


def _scans(monkeypatch: pytest.MonkeyPatch, scans: dict[str, list[dict[str, Any]]]) -> None:
    def fake(target: Path, settings: object, scan: str = "latest") -> store.StoredScan:
        key = "b" if scan == "latest" else scan
        if key not in scans:
            raise store.ScanNotFoundError("no stored scan found; run codekavach scan first")
        return store.StoredScan(f"scan_{key}", target, scans[key], {})

    monkeypatch.setattr(store, "load_scan", fake)


def test_secrets_scan_masks_the_value(project: Path) -> None:
    (project / "settings.py").write_text(f'AWS_KEY = "{EXAMPLE_KEY}"\n', encoding="utf-8")
    result = run_cli(["secrets", "scan", str(project)], home=project.parent / "home")
    assert result.exit_code == 1
    assert "settings.py:1" in result.stdout
    assert EXAMPLE_KEY not in result.stdout + result.stderr
    assert_matches_golden(result.stdout, GOLDEN / "secrets_scan.txt")


def test_secrets_scan_json_has_no_value(project: Path) -> None:
    (project / "settings.py").write_text(f'AWS_KEY = "{EXAMPLE_KEY}"\n', encoding="utf-8")
    result = run_cli(["secrets", "scan", str(project), "--json"], home=project.parent / "home")
    assert result.exit_code == 1
    assert EXAMPLE_KEY not in result.stdout
    envelope = result.json
    assert envelope["command"] == "secrets scan"
    assert envelope["data"]["findings"][0]["type"] == "aws_access_key"
    assert envelope["errors"][0]["code"] == "secrets_found"


def test_secrets_scan_clean_project(project: Path) -> None:
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    result = run_cli(["secrets", "scan", str(project)], home=project.parent / "home")
    assert result.exit_code == 0, result.stderr


def test_secrets_history_finds_removed_credential(project: Path) -> None:
    (project / ".git").rmdir()
    git = ["git", "-C", str(project)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "config", "user.email", "t@example.com"], check=True)
    subprocess.run([*git, "config", "user.name", "t"], check=True)
    (project / "s.py").write_text(f'KEY = "{EXAMPLE_KEY}"\n', encoding="utf-8")
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "add"], check=True)
    (project / "s.py").write_text("KEY = None\n", encoding="utf-8")
    subprocess.run([*git, "commit", "-qam", "remove"], check=True)
    plain = run_cli(["secrets", "scan", str(project)], home=project.parent / "home")
    assert plain.exit_code == 0, plain.stderr
    hist = run_cli(
        ["secrets", "scan", str(project), "--history", "--json"], home=project.parent / "home"
    )
    assert hist.exit_code == 1
    assert EXAMPLE_KEY not in hist.stdout
    assert hist.json["data"]["findings"][0]["commit"]


def test_baseline_create_show_clear(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _scans(monkeypatch, {"b": [_finding("ckfp1:aaaa1"), _finding("ckfp1:aaaa2", line=9)]})
    home = project.parent / "home"
    created = run_cli(["baseline", "create", str(project), "--json"], home=home)
    assert created.exit_code == 0, created.stderr
    assert created.json["data"]["entries"] == 2
    again = run_cli(["baseline", "create", str(project)], home=home)
    assert again.exit_code == 2
    shown = run_cli(["baseline", "show", str(project), "--json"], home=home)
    entries = shown.json["data"]["entries"]
    assert [e["rule_id"] for e in entries] == ["py.sql", "py.sql"]
    assert shown.json["data"]["file"] == ".codekavach/baseline.json"
    cleared = run_cli(["baseline", "clear", str(project), "--json"], home=home)
    assert cleared.json["data"]["removed"] is True
    assert not (project / ".codekavach" / "baseline.json").exists()
    assert (
        run_cli(["baseline", "show", str(project), "--json"], home=home).json["data"]["entries"]
        == []
    )


def test_baseline_create_without_scan_is_usage_error(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scans(monkeypatch, {})
    result = run_cli(["baseline", "create", str(project)], home=project.parent / "home")
    assert result.exit_code == 2


def test_suppress_list_states(project: Path) -> None:
    (project / ".codekavach").mkdir()
    (project / ".codekavach" / "suppressions.yaml").write_text(
        "suppressions:\n"
        "  - rule: iac.docker.root-user\n    path: deploy/**\n    justification: sidecar\n"
        "  - rule: CWE-79\n    path: '**'\n    justification: old\n    expires: 2001-01-01\n",
        encoding="utf-8",
    )
    (project / "a.py").write_text(
        "x = 1  # codekavach:ignore[CWE-89] -- parameterised upstream\n"
        "y = 2  # codekavach:ignore\n",
        encoding="utf-8",
    )
    result = run_cli(["suppress", "list", str(project), "--json"], home=project.parent / "home")
    assert result.exit_code == 1
    rows = result.json["data"]["suppressions"]
    assert sorted(r["state"] for r in rows) == ["active", "active", "expired", "invalid"]
    assert result.json["data"]["inactive"] == 2


def test_suppress_list_empty(project: Path) -> None:
    result = run_cli(["suppress", "list", str(project)], home=project.parent / "home")
    assert result.exit_code == 0
    assert "No suppressions." in result.stdout


def test_diff_reports_new_fixed_unchanged(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _scans(
        monkeypatch,
        {
            "a": [_finding("ckfp1:aaaa1"), _finding("ckfp1:aaaa2")],
            "b": [_finding("ckfp1:aaaa2"), _finding("ckfp1:aaaa3", path="x.py")],
        },
    )
    result = run_cli(
        ["diff", "a", "b", "--target", str(project), "--json"], home=project.parent / "home"
    )
    assert result.exit_code == 1
    data = result.json["data"]
    assert data["counts"] == {"new": 1, "fixed": 1, "unchanged": 1}
    assert data["new"][0]["path"] == "x.py"
    assert data["fixed"][0]["fingerprint"] == "ckfp1:aaaa1"
    assert "evidence" not in json.dumps(data)


def test_diff_without_new_findings_exits_zero(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scans(monkeypatch, {"a": [_finding("ckfp1:aaaa1")], "b": []})
    result = run_cli(["diff", "a", "b", "--target", str(project)], home=project.parent / "home")
    assert result.exit_code == 0, result.stderr
    assert "0 new, 1 fixed" in result.stdout


def test_diff_unknown_scan_is_usage_error(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _scans(monkeypatch, {"a": []})
    result = run_cli(["diff", "a", "zzz", "--target", str(project)], home=project.parent / "home")
    assert result.exit_code == 2
