"""The Action's job summary shows finding titles and paths as literal text."""

import json
import re
import subprocess
import sys
from pathlib import Path

from codekavach.integrations.github.checks import job_summary
from codekavach.integrations.github.findings import normalize

RUN_SH = Path(__file__).resolve().parents[3] / "action" / "run.sh"
TITLE = "<a href=https://evil.example>Critical: rotate keys here</a> [x](https://evil) @org"
PATH = "a` [Rotate keys](https://evil.example) `|b.py"


def _summary_script() -> str:
    text = RUN_SH.read_text(encoding="utf-8")
    match = re.search(r"<<'PY'\n(.*?)\nPY\n", text, re.S)
    assert match, "run.sh no longer embeds the summary script"
    return match[1]


def _assert_literal(summary: str) -> None:
    row = next(line for line in summary.splitlines() if "rotate keys here" in line)
    assert "<a" not in row and "@org" not in row
    assert "\\[x\\]" in row and not re.search(r"(?<!\\)\[x", row)
    # The path stays inside one code span and cannot add table cells.
    assert row.count("`") == 2
    assert len(re.findall(r"(?<!\\)\|", row)) == 4


def test_action_step_summary_escapes_titles_and_paths(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps(
            {
                "data": {
                    "scan_id": "scan_1",
                    "findings": [
                        {
                            "severity": "high",
                            "status": "open",
                            "title": TITLE,
                            "locations": [{"path": PATH, "start_line": 3}],
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    summary = tmp_path / "summary.md"
    env = {"GITHUB_STEP_SUMMARY": str(summary), "GITHUB_OUTPUT": str(tmp_path / "out")}
    subprocess.run(
        [sys.executable, "-", str(findings), "high"],
        input=_summary_script(),
        text=True,
        env=env,
        check=True,
        capture_output=True,
    )
    _assert_literal(summary.read_text(encoding="utf-8"))


def test_job_summary_escapes_titles_and_paths() -> None:
    view = normalize(
        {
            "fingerprint": "ckfp1:" + "0" * 32,
            "title": TITLE,
            "severity": "high",
            "locations": [{"path": PATH, "start_line": 3}],
        }
    )
    _assert_literal(job_summary([view]))
