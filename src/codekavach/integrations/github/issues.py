"""Issue synchronisation: one GitHub issue per finding, idempotent by fingerprint marker.

Owning epic: E34.

Every issue body ends with two hidden markers: ``<!-- codekavach:fp=... -->`` (identity) and
``<!-- codekavach:h=... -->`` (hash of the rendered content). A rerun therefore creates nothing
twice, updates only issues whose content changed, closes issues whose finding is no longer
reported (or was resolved), and reopens an issue whose finding came back. Bodies hold metadata
and a masked snippet; vault contents are never available to this module.
"""

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from codekavach.integrations.github.findings import FindingView, mask_text
from codekavach.integrations.github.transport import GitHubClient, GitHubError

FP_MARKER: Final = re.compile(r"<!--\s*codekavach:fp=(\S+?)\s*-->")
HASH_MARKER: Final = re.compile(r"<!--\s*codekavach:h=([0-9a-f]+)\s*-->")
_INLINE_MARKUP: Final = re.compile(r"([\\`*_\[\]()!#|~])")
_COLOURS: Final = {
    "critical": "b60205",
    "high": "d93f0b",
    "medium": "fbca04",
    "low": "0e8a16",
    "info": "c5def5",
}


@dataclass
class IssueAction:
    """One planned or performed change."""

    action: str  # create | update | close | reopen | skip
    fingerprint: str
    title: str
    severity: str
    number: int | None = None
    url: str | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        """JSON-friendly form."""
        return {k: v for k, v in self.__dict__.items() if v not in (None, "")}


@dataclass
class IssuePlan:
    """The planned actions for a run."""

    actions: list[IssueAction] = field(default_factory=list)

    def count(self, name: str) -> int:
        """How many actions of kind ``name``."""
        return sum(1 for a in self.actions if a.action == name)


def labels_for(finding: FindingView, prefix: str) -> list[str]:
    """Labels of an issue: the prefix, the severity and each CWE."""
    return [
        prefix,
        f"{prefix}:severity-{finding.severity}",
        *(f"{prefix}:{c.lower()}" for c in finding.cwe),
    ]


def render_title(finding: FindingView) -> str:
    """Issue title."""
    return f"[{finding.severity.upper()}] {finding.title}"[:240]


def _text(value: str) -> str:
    """Untrusted free text shown literally: no links, images, HTML, comments or @mentions.

    Descriptions and remediation can come from model output that scanned code may steer, so
    every Markdown control character is escaped, ``&``, ``<`` and ``>`` become entities (which
    also removes any ``<!--`` marker look-alike) and ``@`` is broken with a zero-width space.
    """
    value = value.replace("\r", "")
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    value = _INLINE_MARKUP.sub(r"\\\1", value)
    return re.sub(r"@(?=\w)", "@\u200b", value)


def _code(value: str) -> str:
    """A value for a single-backtick code span: one line, no backtick to break out."""
    return value.replace("`", "'").replace("\r", " ").replace("\n", " ")


def _last(pattern: re.Pattern[str], body: str) -> str | None:
    """The last match of a marker: the real markers always end the body this module writes."""
    matches = pattern.findall(body)
    return str(matches[-1]) if matches else None


def render_body(finding: FindingView) -> str:
    """Issue body without markers: masked, metadata only, untrusted text escaped."""
    parts = [
        f"**Severity:** {_text(finding.severity)}  ",
        f"**Location:** `{_code(finding.path)}:{finding.start_line}`  ",
    ]
    if finding.cwe:
        parts.append(f"**CWE:** {_text(', '.join(finding.cwe))}  ")
    if finding.owasp:
        parts.append(f"**OWASP:** {_text(', '.join(finding.owasp))}  ")
    if finding.rule_id:
        parts.append(f"**Rule:** `{_code(finding.rule_id)}`  ")
    if finding.confidence:
        parts.append(f"**Confidence:** {_text(finding.confidence)}  ")
    if finding.description:
        parts += ["", "### Description", _text(finding.description)]
    if finding.snippet:
        code = "\n".join(f"{n:>4} | {mask_text(t)}" for n, t in finding.snippet)
        parts += ["", "### Code (secrets masked)", "```", code, "```"]
    if finding.remediation:
        parts += ["", "### Remediation", _text(finding.remediation)]
    if finding.references:
        parts += ["", "### References", *(f"- {_text(r)}" for r in finding.references if r)]
    parts += ["", "_Raised by CodeKavach. Closed automatically when the finding is resolved._"]
    return "\n".join(parts)


def render_issue(finding: FindingView) -> tuple[str, str, str]:
    """Title, full body with markers, and content hash."""
    title = render_title(finding)
    body = render_body(finding)
    digest = hashlib.sha256(f"{title}\n{body}".encode()).hexdigest()[:16]
    marked = (
        f"{body}\n\n<!-- codekavach:fp={finding.fingerprint} -->\n<!-- codekavach:h={digest} -->"
    )
    return title, marked, digest


def fetch_existing(client: GitHubClient, repo: str, prefix: str) -> dict[str, dict[str, Any]]:
    """Existing CodeKavach issues of ``repo`` by fingerprint (open and closed, no pull requests)."""
    found: dict[str, dict[str, Any]] = {}
    for item in client.paginate(f"/repos/{repo}/issues", state="all", labels=prefix):
        if "pull_request" in item:
            continue
        fingerprint = _last(FP_MARKER, item.get("body") or "")
        if fingerprint:
            found.setdefault(fingerprint, item)
    return found


def plan_issues(
    findings: Sequence[FindingView],
    existing: dict[str, dict[str, Any]],
    *,
    min_severity: str = "medium",
    close_resolved: bool = True,
    max_issues: int | None = None,
) -> IssuePlan:
    """Decide what to create, update, close or reopen; pure, so dry runs can print it."""
    from codekavach.integrations.github.findings import SEVERITIES  # noqa: PLC0415

    floor = SEVERITIES.index(min_severity) if min_severity in SEVERITIES else 0
    plan = IssuePlan()
    budget = max_issues if max_issues is not None else 10**9
    current = {f.fingerprint for f in findings if f.is_open}
    for finding in sorted(findings, key=lambda f: -f.rank):
        issue = existing.get(finding.fingerprint)
        title = render_title(finding)
        if not finding.is_open or finding.rank < floor:
            if issue and issue["state"] == "open" and close_resolved and not finding.is_open:
                plan.actions.append(_act("close", finding, issue, "finding resolved"))
            continue
        if issue is None:
            if budget <= 0:
                plan.actions.append(
                    IssueAction(
                        "skip",
                        finding.fingerprint,
                        title,
                        finding.severity,
                        reason="max issues reached",
                    )
                )
                continue
            budget -= 1
            plan.actions.append(IssueAction("create", finding.fingerprint, title, finding.severity))
            continue
        _, _, digest = render_issue(finding)
        old = _last(HASH_MARKER, issue.get("body") or "")
        if issue["state"] == "closed":
            plan.actions.append(_act("reopen", finding, issue, "finding reappeared"))
        elif old != digest:
            plan.actions.append(_act("update", finding, issue, "content changed"))
    if close_resolved:
        for fp, issue in existing.items():
            if (
                fp not in current
                and issue["state"] == "open"
                and not any(a.fingerprint == fp for a in plan.actions)
            ):
                plan.actions.append(
                    IssueAction(
                        "close",
                        fp,
                        issue.get("title", ""),
                        "",
                        issue["number"],
                        issue.get("html_url"),
                        "no longer reported",
                    )
                )
    return plan


def _act(action: str, finding: FindingView, issue: dict[str, Any], reason: str) -> IssueAction:
    return IssueAction(
        action, finding.fingerprint, render_title(finding), finding.severity,
        issue["number"], issue.get("html_url"), reason,
    )  # fmt: skip


def ensure_labels(
    client: GitHubClient, repo: str, findings: Sequence[FindingView], prefix: str
) -> None:
    """Create any missing label; an existing one (422) is fine."""
    wanted: dict[str, str] = {prefix: "5319e7"}
    for finding in findings:
        for label in labels_for(finding, prefix):
            wanted.setdefault(
                label,
                _COLOURS.get(finding.severity, "ededed") if "severity-" in label else "ededed",
            )
    for name, colour in wanted.items():
        try:
            client.request(
                "POST", f"/repos/{repo}/labels", json={"name": name, "color": colour}, ok=(422,)
            )
        except GitHubError as error:
            if error.status not in (403, 404):
                raise


def apply_plan(
    client: GitHubClient,
    repo: str,
    plan: IssuePlan,
    findings: Sequence[FindingView],
    existing: dict[str, dict[str, Any]],
    *,
    prefix: str,
) -> list[dict[str, Any]]:
    """Perform the plan; returns each created or updated issue (number, node_id, fingerprint)."""
    by_fp = {f.fingerprint: f for f in findings}
    touched: list[dict[str, Any]] = []
    for act in plan.actions:
        finding = by_fp.get(act.fingerprint)
        if act.action == "skip":
            continue
        if act.action == "create" and finding:
            title, body, _ = render_issue(finding)
            issue = client.request(
                "POST", f"/repos/{repo}/issues",
                json={"title": title, "body": body, "labels": labels_for(finding, prefix)},
            ).json()  # fmt: skip
            act.number, act.url = issue["number"], issue.get("html_url")
            touched.append(
                {
                    "number": issue["number"],
                    "node_id": issue.get("node_id"),
                    "fingerprint": act.fingerprint,
                    "severity": finding.severity,
                }
            )
        elif act.action in ("update", "reopen") and finding and act.number:
            title, body, _ = render_issue(finding)
            payload: dict[str, Any] = {
                "title": title,
                "body": body,
                "labels": labels_for(finding, prefix),
            }
            if act.action == "reopen":
                payload["state"] = "open"
            issue = client.request(
                "PATCH", f"/repos/{repo}/issues/{act.number}", json=payload
            ).json()
            touched.append(
                {
                    "number": act.number,
                    "node_id": issue.get("node_id"),
                    "fingerprint": act.fingerprint,
                    "severity": finding.severity,
                }
            )
        elif act.action == "close" and act.number:
            client.request(
                "POST", f"/repos/{repo}/issues/{act.number}/comments",
                json={"body": f"CodeKavach: closing, {act.reason}."},
            )  # fmt: skip
            client.request(
                "PATCH", f"/repos/{repo}/issues/{act.number}",
                json={"state": "closed", "state_reason": "completed"},
            )  # fmt: skip
    return touched
