"""SARIF 2.1.0 for GitHub code scanning, and its upload.

Owning epic: E34.

The document holds metadata and a masked message only. It respects the documented code scanning
caps (25,000 results per run; 10 MB gzipped) by keeping the most severe results first.
"""

import base64
import gzip
import json
from collections.abc import Sequence
from typing import Any, Final

from codekavach.integrations.github.findings import FindingView
from codekavach.integrations.github.transport import GitHubClient

MAX_RESULTS: Final = 25_000
_LEVEL: Final = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SCORE: Final = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def build_sarif(findings: Sequence[FindingView], *, version: str = "0") -> dict[str, Any]:
    """A SARIF 2.1.0 log with one run for ``findings`` (open ones only)."""
    active = sorted((f for f in findings if f.is_open), key=lambda f: -f.rank)[:MAX_RESULTS]
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in active:
        rule_id = finding.rule_id or (finding.cwe[0] if finding.cwe else "codekavach.finding")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation or finding.title},
                "properties": {
                    "tags": ["security", *finding.cwe, *finding.owasp],
                    "security-severity": _SCORE.get(finding.severity, "1.0"),
                },
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": _LEVEL.get(finding.severity, "note"),
                "message": {"text": finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path or "unknown"},
                            "region": {
                                "startLine": finding.start_line,
                                "endLine": max(finding.start_line, finding.end_line),
                            },
                        }
                    }
                ],
                "partialFingerprints": {"codekavach/v1": finding.fingerprint},
                "properties": {"severity": finding.severity, "confidence": finding.confidence},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeKavach",
                        "version": version,
                        "informationUri": "https://github.com/jatinsingh1603/Source-Code-Review-Tool-TIET",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def upload_sarif(
    client: GitHubClient, repo: str, sarif: dict[str, Any], *, commit_sha: str, ref: str
) -> dict[str, Any]:
    """Upload ``sarif`` to code scanning and return GitHub's answer (id, url)."""
    payload = base64.b64encode(gzip.compress(json.dumps(sarif).encode())).decode()
    body = {"commit_sha": commit_sha, "ref": ref, "sarif": payload, "tool_name": "CodeKavach"}
    answer: dict[str, Any] = client.request(
        "POST", f"/repos/{repo}/code-scanning/sarifs", json=body
    ).json()
    return answer
