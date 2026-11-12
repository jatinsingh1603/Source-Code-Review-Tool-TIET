# ruff: noqa: SIM102
"""GitHub Actions workflow checks."""

import re
from typing import Any, Final

from codekavach.analysis.iac.common import Issue, YMap, load_yaml, walk
from codekavach.core.models import Confidence, Severity

_INJECTABLE: Final = re.compile(
    r"\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.(ref|label)"
    r"|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|"
    r"head_commit\.(message|author\.(name|email))|commits\[[^\]]*\]\.message|pages\[[^\]]*\]\."
    r"page_name|discussion\.(title|body))|github\.head_ref)[^}]*\}\}"
)
_PINNED: Final = re.compile(r"@[0-9a-f]{40}$")
_HEAD_REF: Final = re.compile(r"github\.event\.pull_request\.head\.|github\.head_ref")


def check_workflow(text: str) -> list[Issue]:
    """pull_request_target checkout, script injection, unpinned actions, write-all permissions."""
    issues: list[Issue] = []
    for doc in load_yaml(text):
        if not isinstance(doc, YMap):
            continue
        on: Any = doc.get("on", doc.get("true"))  # YAML 1.1 reads a bare ``on`` as True
        on_keys = (
            set(on) if isinstance(on, dict) else {on} if isinstance(on, str) else set(on or [])
        )
        target = "pull_request_target" in on_keys
        _permissions(doc, issues)
        jobs = doc.get("jobs")
        if not isinstance(jobs, YMap):
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, YMap):
                continue
            _permissions(job, issues)
            steps = job.get("steps")
            for step in steps if isinstance(steps, list) else []:
                if isinstance(step, YMap):
                    _step(step, str(job_name), target, issues)
    return issues


def _permissions(node: YMap, issues: list[Issue]) -> None:
    perm = node.get("permissions")
    if isinstance(perm, str) and perm.strip().lower() == "write-all":
        issues.append(
            Issue(
                "iac.actions.write-all-permissions",
                node.line_of("permissions"),
                Severity.MEDIUM,
                250,
                "The workflow grants write-all permissions to the token.",
            )
        )


def _step(step: YMap, job: str, target: bool, issues: list[Issue]) -> None:
    uses = step.get("uses")
    if isinstance(uses, str):
        ref = uses.strip()
        if not ref.startswith(("./", "docker://")) and not _PINNED.search(ref):
            issues.append(
                Issue(
                    "iac.actions.unpinned-action",
                    step.line_of("uses"),
                    Severity.LOW,
                    829,
                    f"Action reference in job '{job}' is not pinned to a commit SHA, so a moved "
                    "tag changes what runs.",
                    Confidence.MEDIUM,
                )
            )
        if target and ref.startswith("actions/checkout"):
            with_ = step.get("with")
            ref_value = str(with_.get("ref", "")) if isinstance(with_, YMap) else ""
            if _HEAD_REF.search(ref_value):
                issues.append(
                    Issue(
                        "iac.actions.pull-request-target-checkout",
                        with_.line_of("ref") if isinstance(with_, YMap) else step.line,
                        Severity.CRITICAL,
                        829,
                        "A pull_request_target workflow checks out the pull request head, "
                        "running untrusted code with repository secrets and a write token.",
                    )
                )
    run = step.get("run")
    if isinstance(run, str) and _INJECTABLE.search(run):
        issues.append(
            Issue(
                "iac.actions.script-injection",
                step.line_of("run"),
                Severity.HIGH,
                78,
                f"A run step in job '{job}' interpolates attacker-controlled event data into "
                "a shell script; pass it through an environment variable instead.",
            )
        )
    script = step.get("with")
    if isinstance(script, YMap) and isinstance(script.get("script"), str):
        if _INJECTABLE.search(script["script"]):
            issues.append(
                Issue(
                    "iac.actions.script-injection",
                    script.line_of("script"),
                    Severity.HIGH,
                    94,
                    "A github-script step interpolates attacker-controlled event data.",
                )
            )


__all__ = ["check_workflow", "walk"]
