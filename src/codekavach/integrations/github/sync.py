"""GitHub sync entry points: ``sync_findings`` (server) and ``run_github_sync`` (CLI).

Owning epic: E34.

``sync_findings(scan, repo, token, dry_run)`` returns ``{created, updated, closed, items}``. In a
dry run no write is made. With a token a dry run still reads the repository (GET only) so it
reports exactly what a real run would do; without a token it assumes an empty repository and says
so. Outbound GitHub calls are not LLM egress; they honour ``offline`` and are documented in
``docs/reference/cli-network-behaviour.md``.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codekavach.core.log import get_logger
from codekavach.integrations.github import issues as issue_sync
from codekavach.integrations.github.findings import normalize_all, scan_findings
from codekavach.integrations.github.projects import sync_board
from codekavach.integrations.github.transport import DEFAULT_API_URL, GitHubClient, GitHubError

_LOG = get_logger(__name__)
_REF_PREFIXES = ("env:", "file:", "keyring:")


def resolve_token(token: str | None) -> str | None:
    """A literal token, or the value behind an ``env:``/``file:``/``keyring:`` reference."""
    if not token:
        return None
    if token.startswith(_REF_PREFIXES):
        from codekavach.config.keys import resolve_secret  # noqa: PLC0415

        return resolve_secret(token).get_secret_value()
    return token


def _write_state(path: Path | None, repo: str, items: list[dict[str, Any]]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    current = {i["fingerprint"]: i["number"] for i in items if i.get("number")}
    previous: dict[str, Any] = {}
    if path.is_file():
        try:
            previous = json.loads(path.read_text(encoding="utf-8")).get("issues", {})
        except ValueError:
            previous = {}
    state = {"repo": repo, "issues": {**previous, **current}}
    path.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")


def sync_findings(
    scan: Any,
    repo: str,
    token: str | None,
    dry_run: bool = True,
    *,
    api_url: str = DEFAULT_API_URL,
    prefix: str = "codekavach",
    min_severity: str = "medium",
    close_resolved: bool = True,
    max_issues: int | None = None,
    project_owner: str | None = None,
    project_number: int | None = None,
    offline: bool = False,
    state_path: Path | None = None,
    client: GitHubClient | None = None,
) -> dict[str, Any]:
    """Create, update and close one issue per finding of ``scan`` in ``repo``.

    ``scan`` is a scan object with ``findings``, a ``{"findings": [...]}`` mapping or a list.
    ``token`` is a token or a reference (``env:GITHUB_TOKEN``).

    Raises:
        GitHubError: a GitHub call failed after retries.
    """
    findings = normalize_all(scan_findings(scan))
    secret = resolve_token(token)
    owned = client is None
    api = client or GitHubClient(secret, api_url=api_url, offline=offline)
    notes: list[str] = []
    try:
        existing: dict[str, dict[str, Any]] = {}
        if api.has_token or not owned:
            if offline:
                notes.append("offline: existing issues were not read")
            else:
                existing = issue_sync.fetch_existing(api, repo, prefix)
        else:
            notes.append("no token: assuming the repository has no CodeKavach issues yet")
        plan = issue_sync.plan_issues(
            findings,
            existing,
            min_severity=min_severity,
            close_resolved=close_resolved,
            max_issues=max_issues,
        )
        touched: list[dict[str, Any]] = []
        board: dict[str, int] | None = None
        if not dry_run:
            issue_sync.ensure_labels(api, repo, findings, prefix)
            try:
                touched = issue_sync.apply_plan(api, repo, plan, findings, existing, prefix=prefix)
            finally:
                _write_state(state_path, repo, touched)
            if project_owner and project_number:
                try:
                    board = sync_board(api, project_owner, project_number, touched)
                except GitHubError as error:
                    notes.append(f"project board skipped: {error}")
        return {
            "repo": repo,
            "dry_run": dry_run,
            "created": plan.count("create"),
            "updated": plan.count("update") + plan.count("reopen"),
            "closed": plan.count("close"),
            "skipped": plan.count("skip"),
            "items": [a.as_dict() for a in plan.actions],
            "board": board,
            "notes": notes,
        }
    finally:
        if owned:
            api.close()


def run_github_sync(
    *,
    target: Path,
    scan: str,
    repo: str | None,
    project: str | None,
    issues: bool,
    board: bool,
    dry_run: bool,
    max_issues: int | None,
    settings: Any,
    offline: bool = False,
) -> Mapping[str, Any]:
    """Back end of ``codekavach sync github``."""
    from codekavach.cli.errors import UsageError  # noqa: PLC0415
    from codekavach.integrations.store import load_scan  # noqa: PLC0415

    gh = settings.integrations.github
    if not repo:
        raise UsageError("no repository: pass --repo OWNER/NAME", code="repo_missing")
    stored = load_scan(target, settings, scan)
    owner = number = None
    if board and project:
        owner = gh.project_owner or repo.split("/")[0]
        number = int(project) if project.isdigit() else int(project.rstrip("/").rsplit("/", 1)[-1])
    elif board and gh.project_number:
        owner, number = gh.project_owner or repo.split("/")[0], gh.project_number
    token = str(gh.token) if gh.token else "env:GITHUB_TOKEN"
    try:
        resolved = resolve_token(token)
    except Exception:  # noqa: BLE001 - a missing token is fine for a dry run
        resolved = None
        if not dry_run:
            raise UsageError(
                "no GitHub token: set GITHUB_TOKEN or integrations.github.token",
                code="token_missing",
            ) from None
    if not issues:
        return {
            "repo": repo,
            "created": 0,
            "updated": 0,
            "closed": 0,
            "items": [],
            "notes": ["--no-issues"],
        }
    try:
        return sync_findings(
            stored.findings,
            repo,
            resolved,
            dry_run,
            api_url=str(gh.api_url),
            prefix=gh.labels_prefix,
            min_severity=gh.min_severity_for_issues.value,
            close_resolved=gh.close_resolved,
            max_issues=max_issues or gh.max_issues_per_run,
            project_owner=owner,
            project_number=number,
            offline=offline,
            state_path=Path(stored.state_dir) / "github-sync.json",
        )
    except GitHubError as error:
        raise UsageError(str(error), code="github_error") from None
