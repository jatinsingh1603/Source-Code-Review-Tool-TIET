"""Check runs with annotations, one batched pull-request review and a job summary.

Owning epic: E34.

Each feature degrades on its own: a missing permission (403/404) returns a ``skipped`` result with a
reason instead of failing the run.
"""

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from codekavach.integrations.github.findings import FindingView
from codekavach.integrations.github.issues import md_code, md_text
from codekavach.integrations.github.transport import GitHubClient, GitHubError

ANNOTATION_BATCH: Final = 50
MAX_ANNOTATIONS: Final = 500
_LEVEL: Final = {"critical": "failure", "high": "failure", "medium": "warning"}
_ICON: Final = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _annotation(finding: FindingView) -> dict[str, Any]:
    return {
        "path": finding.path or "unknown",
        "start_line": finding.start_line,
        "end_line": max(finding.start_line, finding.end_line),
        "annotation_level": _LEVEL.get(finding.severity, "notice"),
        "title": f"[{finding.severity.upper()}] {finding.title}"[:255],
        "message": (finding.remediation or finding.description or finding.title)[:60000],
    }


def conclusion_for(findings: Sequence[FindingView], fail_on: str = "high") -> str:
    """``failure`` when an open finding reaches ``fail_on``, else ``success``."""
    from codekavach.integrations.github.findings import SEVERITIES  # noqa: PLC0415

    floor = SEVERITIES.index(fail_on) if fail_on in SEVERITIES else 3
    return "failure" if any(f.is_open and f.rank >= floor for f in findings) else "success"


def create_check_run(
    client: GitHubClient,
    repo: str,
    head_sha: str,
    findings: Sequence[FindingView],
    *,
    fail_on: str = "high",
) -> dict[str, Any]:
    """Create a completed check run and attach annotations in batches of 50."""
    active = sorted((f for f in findings if f.is_open), key=lambda f: -f.rank)
    annotations = [_annotation(f) for f in active[:MAX_ANNOTATIONS]]
    summary = f"{len(active)} open finding(s)."
    output = {"title": "CodeKavach security review", "summary": summary}
    body: dict[str, Any] = {
        "name": "CodeKavach",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": conclusion_for(findings, fail_on),
        "output": {**output, "annotations": annotations[:ANNOTATION_BATCH]},
    }
    try:
        run = client.request("POST", f"/repos/{repo}/check-runs", json=body).json()
        for start in range(ANNOTATION_BATCH, len(annotations), ANNOTATION_BATCH):
            batch = annotations[start : start + ANNOTATION_BATCH]
            client.request(
                "PATCH",
                f"/repos/{repo}/check-runs/{run['id']}",
                json={"output": {**output, "annotations": batch}},
            )
    except GitHubError as error:
        if error.status in (403, 404):
            return {"skipped": True, "reason": "checks need a GitHub App or Actions token"}
        raise
    return {"skipped": False, "id": run["id"], "annotations": len(annotations)}


def post_review(
    client: GitHubClient, repo: str, pull: int, head_sha: str, findings: Sequence[FindingView]
) -> dict[str, Any]:
    """Post one review with an inline comment per open finding (max 50)."""
    active = sorted((f for f in findings if f.is_open and f.path), key=lambda f: -f.rank)[:50]
    if not active:
        return {"skipped": True, "reason": "no findings to comment on"}
    comments = [
        {
            "path": f.path,
            "line": max(f.start_line, f.end_line),
            "side": "RIGHT",
            "body": f"**{_ICON.get(f.severity, 'INFO')}**: {f.title}\n\n{f.remediation}".strip(),
        }
        for f in active
    ]
    body = {
        "commit_id": head_sha,
        "event": "COMMENT",
        "body": f"CodeKavach found {len(active)} issue(s) in this change.",
        "comments": comments,
    }
    try:
        review = client.request("POST", f"/repos/{repo}/pulls/{pull}/reviews", json=body).json()
    except GitHubError as error:
        if error.status in (403, 404, 422):
            return {"skipped": True, "reason": f"review refused (HTTP {error.status})"}
        raise
    return {"skipped": False, "id": review.get("id"), "comments": len(comments)}


def job_summary(findings: Sequence[FindingView]) -> str:
    """Markdown for ``$GITHUB_STEP_SUMMARY``."""
    active = sorted((f for f in findings if f.is_open), key=lambda f: -f.rank)
    lines = ["## CodeKavach security review", "", f"{len(active)} open finding(s).", ""]
    if active:
        lines += ["| Severity | Finding | Location |", "|---|---|---|"]
        for f in active[:100]:
            title = md_text(f.title.replace("\n", " "))
            where = md_code(f"{f.path}:{f.start_line}").replace("|", "\\|")
            lines.append(f"| {md_text(f.severity)} | {title} | `{where}` |")
    return "\n".join(lines) + "\n"


def write_job_summary(findings: Sequence[FindingView], path: str | None = None) -> bool:
    """Append the summary to ``$GITHUB_STEP_SUMMARY`` (or ``path``); False when unset."""
    target = path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return False
    with Path(target).open("a", encoding="utf-8") as handle:
        handle.write(job_summary(findings))
    return True
