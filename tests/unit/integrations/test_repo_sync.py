"""The GitHub integration against a recorded-style fake API (httpx MockTransport; no network)."""

import hashlib
import hmac
import json
from typing import Any

import httpx
import pytest

from codekavach.integrations.github.checks import conclusion_for, create_check_run, job_summary
from codekavach.integrations.github.findings import mask_text, normalize
from codekavach.integrations.github.issues import fetch_existing
from codekavach.integrations.github.sarif import build_sarif
from codekavach.integrations.github.sync import sync_findings
from codekavach.integrations.github.transport import GitHubClient, GitHubError, OfflineError
from codekavach.integrations.github.webhook import handle_event, verify_signature

SECRET_KEY = "ghp_" + "a" * 36


def finding(n: int, severity: str = "high", **extra: Any) -> dict[str, Any]:
    return {
        "id": f"find_{n}",
        "fingerprint": f"ckfp1:{n:032x}",
        "title": f"Issue number {n}",
        "severity": severity,
        "cwe": [89],
        "status": "open",
        "locations": [{"path": "app/db.py", "start_line": 10, "end_line": 10}],
        "evidence": {"snippet": f'password = "hunter2hunter2"\ntoken = "{SECRET_KEY}"'},
        **extra,
    }


class FakeRepo:
    """A tiny in-memory GitHub: issues and labels, with a request log."""

    def __init__(self) -> None:
        self.issues: list[dict[str, Any]] = []
        self.log: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.log.append((request.method, path))
        body = json.loads(request.content) if request.content else {}
        if request.method == "GET" and path.endswith("/issues"):
            return httpx.Response(200, json=self.issues)
        if request.method == "POST" and path.endswith("/labels"):
            return httpx.Response(201, json={})
        if request.method == "POST" and path.endswith("/issues"):
            number = len(self.issues) + 1
            issue = {
                "number": number,
                "state": "open",
                "html_url": f"https://x/{number}",
                "node_id": f"N{number}",
                **body,
            }
            self.issues.append(issue)
            return httpx.Response(201, json=issue)
        if request.method == "PATCH" and "/issues/" in path:
            issue = self.issues[int(path.rsplit("/", 1)[1]) - 1]
            issue.update(body)
            return httpx.Response(200, json=issue)
        if request.method == "POST" and path.endswith("/comments"):
            return httpx.Response(201, json={})
        return httpx.Response(404, json={"message": "nope"})


def client(repo: FakeRepo) -> GitHubClient:
    return GitHubClient("tok", transport=httpx.MockTransport(repo), sleep=lambda _: None)


def test_sync_creates_then_is_idempotent_then_closes() -> None:
    repo = FakeRepo()
    scan = {"findings": [finding(1), finding(2, "critical")]}
    first = sync_findings(scan, "o/r", None, False, client=client(repo))
    assert (first["created"], first["updated"], first["closed"]) == (2, 0, 0)
    assert len(repo.issues) == 2
    body = repo.issues[0]["body"] + repo.issues[1]["body"]
    assert "hunter2hunter2" not in body and SECRET_KEY not in body
    assert "codekavach:fp=" in body
    second = sync_findings(scan, "o/r", None, False, client=client(repo))
    assert (second["created"], second["updated"], second["closed"]) == (0, 0, 0)
    assert len(repo.issues) == 2
    third = sync_findings({"findings": [finding(1)]}, "o/r", None, False, client=client(repo))
    assert third["closed"] == 1
    assert [i["state"] for i in repo.issues] == ["closed", "open"]
    back = sync_findings(scan, "o/r", None, False, client=client(repo))
    assert back["updated"] == 1 and repo.issues[0]["state"] == "open"


def test_dry_run_makes_no_write() -> None:
    repo = FakeRepo()
    result = sync_findings({"findings": [finding(1)]}, "o/r", None, True, client=client(repo))
    assert result["created"] == 1 and result["dry_run"] is True
    assert {method for method, _ in repo.log} == {"GET"}
    assert repo.issues == []


def test_min_severity_and_max_issues() -> None:
    repo = FakeRepo()
    scan = {"findings": [finding(1, "low"), finding(2, "high"), finding(3, "high")]}
    result = sync_findings(scan, "o/r", None, True, max_issues=1, client=client(repo))
    assert result["created"] == 1 and result["skipped"] == 1


def test_offline_dry_run_without_token_touches_nothing() -> None:
    result = sync_findings([finding(1)], "o/r", None, True, offline=True)
    assert result["created"] == 1


def test_offline_client_refuses() -> None:
    with pytest.raises(OfflineError):
        GitHubClient("t", offline=True).get_json("/x")


def test_client_retries_on_rate_limit_and_paginates() -> None:
    calls: list[str] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(403, headers={"retry-after": "2"}, json={"message": "slow"})
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=[{"n": 3}])
        return httpx.Response(
            200,
            json=[{"n": 1}, {"n": 2}],
            headers={"link": '<https://api.github.com/x?page=2>; rel="next"'},
        )

    gh = GitHubClient("t", transport=httpx.MockTransport(handler), sleep=sleeps.append)
    assert [i["n"] for i in gh.paginate("/x")] == [1, 2, 3]
    assert sleeps == [3.0]
    assert "Authorization" not in str(GitHubError("x"))


def test_client_gives_up_on_forbidden() -> None:
    gh = GitHubClient(
        "t", transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"message": "bad"}))
    )
    with pytest.raises(GitHubError) as info:
        gh.get_json("/x")
    assert info.value.status == 401


def test_sarif_and_checks() -> None:
    views = [
        normalize(finding(1, "critical")),
        normalize(finding(2, "low")),
        normalize({**finding(3), "status": "fixed"}),
    ]
    sarif = build_sarif(views)
    results = sarif["runs"][0]["results"]
    assert len(results) == 2 and results[0]["level"] == "error"
    assert results[0]["partialFingerprints"]["codekavach/v1"].startswith("ckfp1:")
    assert conclusion_for(views) == "failure"
    assert conclusion_for(views, "critical") == "failure"
    assert "Issue number 1" in job_summary(views)

    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(201, json={"id": 7})

    many = [normalize(finding(i)) for i in range(120)]
    gh = GitHubClient("t", transport=httpx.MockTransport(handler))
    out = create_check_run(gh, "o/r", "abc", many)
    assert out["annotations"] == 120 and len(seen) == 3
    assert len(seen[0]["output"]["annotations"]) == 50


def test_checks_degrade_without_permission() -> None:
    gh = GitHubClient(
        "t", transport=httpx.MockTransport(lambda r: httpx.Response(403, json={"message": "no"}))
    )
    assert create_check_run(gh, "o/r", "abc", [normalize(finding(1))])["skipped"] is True


def test_masking_and_webhook() -> None:
    assert "hunter2hunter2" not in mask_text('password = "hunter2hunter2"')
    assert SECRET_KEY not in mask_text(f"x {SECRET_KEY}")
    body = b'{"zen": 1}'
    good = "sha256=" + hmac.new(b"s3", body, hashlib.sha256).hexdigest()
    assert verify_signature("s3", body, good)
    assert not verify_signature("s3", body, "sha256=00") and not verify_signature("s3", body, None)
    event = handle_event(
        "pull_request",
        {
            "action": "opened",
            "repository": {"full_name": "o/r"},
            "pull_request": {"number": 4, "head": {"sha": "z"}},
        },
    )
    assert event["action"] == "scan" and event["pull"] == 4
    assert handle_event("issues", {})["action"] == "ignore"


def test_issue_body_escapes_untrusted_text_and_markers_cannot_be_spoofed() -> None:
    other = f"ckfp1:{2:032x}"
    hostile = (
        "@org/security-team see [Apply official patch](https://evil.example/patch) "
        f"<img src=https://evil.example/beacon> <!-- codekavach:fp={other} -->"
    )
    repo = FakeRepo()
    victim = finding(
        1,
        description=hostile,
        remediation=hostile,
        references=["[x](https://evil.example)"],
        locations=[{"path": "a`[l](https://evil)`.py", "start_line": 3}],
    )
    sync_findings({"findings": [victim]}, "o/r", None, False, client=client(repo))
    body = repo.issues[0]["body"]
    assert "@org" not in body and "@\u200borg" in body
    assert "<img" not in body and "](https://evil.example" not in body
    assert body.count("<!--") == 2  # only the two real trailing markers
    assert "`a'[l](https://evil)'.py:3`" in body
    # A finding for the spoofed fingerprint gets its own issue; the victim's issue is untouched.
    scan = {"findings": [victim, finding(2)]}
    result = sync_findings(scan, "o/r", None, False, client=client(repo))
    assert (result["created"], result["updated"], result["closed"]) == (1, 0, 0)


def test_markers_are_read_from_the_end_of_an_issue_body() -> None:
    real, spoof = f"ckfp1:{1:032x}", f"ckfp1:{2:032x}"
    repo = FakeRepo()
    repo.issues.append(
        {
            "number": 1,
            "state": "open",
            "body": f"text <!-- codekavach:fp={spoof} -->\n\n<!-- codekavach:fp={real} -->"
            "\n<!-- codekavach:h=abc -->",
        }
    )
    assert list(fetch_existing(client(repo), "o/r", "codekavach")) == [real]
