"""The REST API end to end with FastAPI's TestClient: auth, roles, projects, a real scan.

One module-scoped server scans the KavachBank sample with the mock provider through the real
pipeline; the other cases read that scan's findings, privacy summary, ledger, events and reports.
"""

import io
import json
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from codekavach.core.pipeline.cancel import CancellationToken
from codekavach.server import audit
from codekavach.server.app import create_app
from codekavach.server.config import ServerConfig
from codekavach.server.jobs.scan import ScanJob, execute_scan

pytest.importorskip("fastapi")

ADMIN = {"username": "admin", "password": "kavach-admin"}


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[TestClient, Any]]:
    data = tmp_path_factory.mktemp("server-data")
    config = ServerConfig(
        data_dir=data, ui_dir=None, workers=2, admin_password="kavach-admin",
        login_attempts_per_minute=1000,
    )  # fmt: skip
    app = create_app(config)
    with TestClient(app) as client:
        yield client, app.state.server


@pytest.fixture(scope="module")
def admin(server: tuple[TestClient, Any]) -> dict[str, str]:
    return _login(server[0], **ADMIN)


@pytest.fixture(scope="module")
def users(server: tuple[TestClient, Any], admin: dict[str, str]) -> dict[str, dict[str, str]]:
    client = server[0]
    headers = {}
    for role in ("auditor", "developer", "viewer"):
        body = {"username": f"{role}1", "password": f"{role}-password", "role": role}
        response = client.post("/api/v1/users", json=body, headers=admin)
        assert response.status_code == 201, response.text
        headers[role] = _login(client, f"{role}1", f"{role}-password")
    return headers


@pytest.fixture(scope="module")
def scan(server: tuple[TestClient, Any], admin: dict[str, str]) -> dict[str, Any]:
    client, state = server
    projects = client.get("/api/v1/projects", headers=admin).json()
    sample = next(item for item in projects if item["source"]["type"] == "sample")
    created = client.post(
        f"/api/v1/projects/{sample['id']}/scans",
        json={"privacy_level": "L2", "provider": "mock", "send": True},
        headers=admin,
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]
    state.runner.wait(scan_id, timeout=300)
    deadline = time.time() + 60
    body: dict[str, Any] = {}
    while time.time() < deadline:
        body = client.get(f"/api/v1/scans/{scan_id}", headers=admin).json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            break
        time.sleep(0.2)
    assert body["status"] == "completed", body
    return dict(body)


def test_health_and_version_are_public(server: tuple[TestClient, Any]) -> None:
    client = server[0]
    assert client.get("/api/v1/health").json()["status"] == "ok"
    assert client.get("/api/v1/version").json()["api"] == "v1"


def test_login_me_logout(server: tuple[TestClient, Any]) -> None:
    client = server[0]
    headers = _login(client, **ADMIN)
    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["role"] == "admin"
    assert "password_hash" not in me.json()
    assert me.headers["Cache-Control"] == "no-store"
    assert me.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in me.headers["Content-Security-Policy"]
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_wrong_password_and_unknown_user_look_the_same(server: tuple[TestClient, Any]) -> None:
    client = server[0]
    wrong = client.post("/api/v1/auth/login", json={"username": "admin", "password": "nope"})
    unknown = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["error"]["code"] == unknown.json()["error"]["code"]


def test_requests_without_a_token_are_refused(server: tuple[TestClient, Any]) -> None:
    client = server[0]
    response = client.get("/api/v1/projects")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_roles(
    server: tuple[TestClient, Any], admin: dict[str, str], users: dict[str, dict[str, str]]
) -> None:
    client, state = server
    viewer, developer = users["viewer"], users["developer"]
    assert client.get("/api/v1/projects", headers=viewer).status_code == 200
    body = {"name": "x", "source": {"type": "sample"}}
    assert client.post("/api/v1/projects", json=body, headers=viewer).status_code == 403
    assert client.get("/api/v1/users", headers=developer).status_code == 403
    assert client.put("/api/v1/settings", json={}, headers=developer).status_code == 403
    audit.flush(state.db)
    log = client.get("/api/v1/audit", headers=admin).json()
    assert log["chain_intact"]
    assert any(event["outcome"] == "denied" for event in log["events"])


def test_project_crud(
    server: tuple[TestClient, Any], users: dict[str, dict[str, str]], tmp_path: Path
) -> None:
    client = server[0]
    developer = users["developer"]
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    created = client.post(
        "/api/v1/projects",
        json={
            "name": "Local",
            "description": "d",
            "source": {"type": "path", "path": str(tmp_path)},
        },
        headers=developer,
    )
    assert created.status_code == 201, created.text
    project_id = created.json()["id"]
    patched = client.patch(
        f"/api/v1/projects/{project_id}", json={"name": "Renamed"}, headers=developer
    )
    assert patched.json()["name"] == "Renamed"
    assert client.get(f"/api/v1/projects/{project_id}", headers=developer).status_code == 200
    bad = client.post(
        "/api/v1/projects",
        json={"name": "Bad", "source": {"type": "git", "url": "http://example.com/x.git"}},
        headers=developer,
    )
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "git_url_scheme"
    assert client.delete(f"/api/v1/projects/{project_id}", headers=developer).status_code == 200
    assert client.get(f"/api/v1/projects/{project_id}", headers=developer).status_code == 404


def test_upload_accepts_a_zip_and_refuses_zip_slip(
    server: tuple[TestClient, Any], admin: dict[str, str]
) -> None:
    client = server[0]
    project = client.post(
        "/api/v1/projects", json={"name": "Upload", "source": {"type": "upload"}}, headers=admin
    ).json()
    good = io.BytesIO()
    with zipfile.ZipFile(good, "w") as bundle:
        bundle.writestr("proj/app.py", "import os\nos.system(input())\n")
    response = client.post(
        f"/api/v1/projects/{project['id']}/upload",
        files={"file": ("proj.zip", good.getvalue(), "application/zip")},
        headers=admin,
    )
    assert response.status_code == 200, response.text
    assert response.json()["files"] == 1
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as bundle:
        bundle.writestr("../../evil.py", "x")
    refused = client.post(
        f"/api/v1/projects/{project['id']}/upload",
        files={"file": ("evil.zip", evil.getvalue(), "application/zip")},
        headers=admin,
    )
    assert refused.status_code == 400
    assert refused.json()["error"]["code"] == "archive_path_traversal"


def test_scan_runs_the_pipeline(scan: dict[str, Any]) -> None:
    assert scan["findings_total"] > 0
    assert scan["progress"] == 100
    assert scan["counts"]["critical"] + scan["counts"]["high"] > 0
    assert "python" in scan["languages"]


def test_findings_list_filter_detail_and_triage(
    server: tuple[TestClient, Any], scan: dict[str, Any], users: dict[str, dict[str, str]]
) -> None:
    client = server[0]
    developer, viewer = users["developer"], users["viewer"]
    findings = client.get(f"/api/v1/scans/{scan['id']}/findings", headers=viewer).json()
    assert len(findings) == scan["findings_total"]
    critical = client.get(
        f"/api/v1/scans/{scan['id']}/findings?severity=critical", headers=viewer
    ).json()
    assert critical
    assert all(item["severity"] == "critical" for item in critical)
    first = next(item for item in findings if item["llm_reviewed"])
    detail = client.get(f"/api/v1/findings/{first['id']}", headers=viewer).json()
    assert detail["evidence"]["code"]["lines"]
    assert detail["evidence"]["snippet"]
    assert detail["cwe"].startswith("CWE-")
    assert detail["llm"]["provider"] == "mock"
    assert detail["llm_verdict"]["provider"] == "mock"
    denied = client.patch(f"/api/v1/findings/{first['id']}", json={"status": "confirmed"},
                          headers=viewer)  # fmt: skip
    assert denied.status_code == 403
    patched = client.patch(
        f"/api/v1/findings/{first['id']}",
        json={"status": "false_positive", "comment": "input is validated upstream"},
        headers=developer,
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "false_positive"
    history = client.get(f"/api/v1/findings/{first['id']}/history", headers=viewer).json()
    assert history[-1]["to_status"] == "false_positive"
    assert history[-1]["comment"] == "input is validated upstream"
    # Choosing the status it already has records nothing.
    same = client.patch(f"/api/v1/findings/{first['id']}", json={"status": "false_positive"},
                        headers=developer)  # fmt: skip
    assert same.status_code == 200
    again = client.get(f"/api/v1/findings/{first['id']}/history", headers=viewer).json()
    assert len(again) == len(history)


def test_privacy_summary(
    server: tuple[TestClient, Any], scan: dict[str, Any], users: dict[str, dict[str, str]]
) -> None:
    client = server[0]
    assert client.get(f"/api/v1/scans/{scan['id']}/privacy",
                      headers=users["viewer"]).status_code == 403  # fmt: skip
    privacy = client.get(f"/api/v1/scans/{scan['id']}/privacy", headers=users["developer"]).json()
    assert privacy["level"] == "L2"
    assert privacy["payloads"] > 0
    assert privacy["chain_ok"] is True
    assert privacy["zero_leak"]["checked"] > 0
    assert privacy["zero_leak"]["passed"] is True
    assert privacy["attestation_text"]
    assert 0 <= privacy["privacy_score"] <= 100


def test_ledger_and_original_versus_sent(
    server: tuple[TestClient, Any], scan: dict[str, Any], users: dict[str, dict[str, str]]
) -> None:
    client = server[0]
    ledger = client.get(f"/api/v1/scans/{scan['id']}/ledger", headers=users["developer"]).json()
    assert ledger["count"] > 0
    entry = ledger["entries"][0]
    assert len(entry["entry_hash"]) == 64
    url = f"/api/v1/scans/{scan['id']}/ledger/{entry['seq']}"
    assert client.get(url, headers=users["developer"]).status_code == 403
    pair = client.get(url, headers=users["auditor"]).json()
    assert pair["payload_text"]
    assert pair["original_text"]
    assert pair["payload_text"] != pair["original_text"]
    verified = client.post(
        f"/api/v1/scans/{scan['id']}/ledger/verify", headers=users["developer"]
    ).json()
    assert verified["ok"] is True


def test_events_replay_until_done(
    server: tuple[TestClient, Any], scan: dict[str, Any], admin: dict[str, str]
) -> None:
    client = server[0]
    response = client.get(f"/api/v1/scans/{scan['id']}/events", headers=admin)
    assert response.headers["content-type"].startswith("text/event-stream")
    kinds = [line.split(": ", 1)[1] for line in response.text.splitlines()
             if line.startswith("event: ")]  # fmt: skip
    assert {"stage", "progress", "finding", "done"} <= set(kinds)
    assert set(kinds) <= {"stage", "progress", "log", "finding", "egress", "done"}
    ids = [int(line[4:]) for line in response.text.splitlines() if line.startswith("id: ")]
    resumed = client.get(
        f"/api/v1/scans/{scan['id']}/events", headers={**admin, "Last-Event-ID": str(ids[-3])}
    )
    again = [int(line[4:]) for line in resumed.text.splitlines() if line.startswith("id: ")]
    assert again == ids[-2:]
    # No source line of the fixture appears in the stream.
    assert "subprocess.run" not in response.text


def test_reports(
    server: tuple[TestClient, Any], scan: dict[str, Any], users: dict[str, dict[str, str]]
) -> None:
    client = server[0]
    listing = client.get(f"/api/v1/scans/{scan['id']}/reports", headers=users["viewer"]).json()
    formats = {item["format"] for item in listing["formats"]}
    assert "html" in formats
    html = client.get(f"/api/v1/scans/{scan['id']}/reports/html", headers=users["viewer"])
    assert html.status_code == 200
    assert "attachment" in html.headers["content-disposition"]
    assert b"<html" in html.content.lower()
    project = client.get(f"/api/v1/projects/{scan['project_id']}", headers=users["viewer"]).json()
    assert f"<title>Secure Source Code Review Report: {project['name']}".encode() in html.content
    missing = client.get(f"/api/v1/scans/{scan['id']}/reports/nope", headers=users["viewer"])
    assert missing.status_code == 404
    assert "markdown" not in formats  # an alias of md, listed once
    assert "manifest" in formats


def test_compliance_annex_never_replaces_the_html_report(
    server: tuple[TestClient, Any], scan: dict[str, Any], users: dict[str, dict[str, str]]
) -> None:
    client = server[0]
    base = f"/api/v1/scans/{scan['id']}/reports"
    annex = client.get(f"{base}/compliance", headers=users["viewer"])
    assert annex.status_code == 200
    assert annex.headers["content-disposition"].endswith('.compliance.html"')
    html = client.get(f"{base}/html", headers=users["viewer"])
    assert html.content != annex.content
    manifest = client.get(f"{base}/manifest", headers=users["viewer"])
    if manifest.status_code == 200:
        files = {item["file"] for item in manifest.json()["files"]}
        assert {"report.html", "report.compliance.html"} <= files


def test_stats_and_settings(
    server: tuple[TestClient, Any], scan: dict[str, Any], admin: dict[str, str]
) -> None:
    client = server[0]
    stats = client.get("/api/v1/stats", headers=admin).json()
    assert stats["scans"] >= 1
    assert sum(stats["findings_by_severity"].values()) > 0
    assert stats["trend"]
    updated = client.put("/api/v1/settings", json={"org_name": "Thapar CSED"}, headers=admin)
    assert updated.json()["org_name"] == "Thapar CSED"
    literal = client.put(
        "/api/v1/settings",
        json={"provider_key_refs": {"agentrouter": "sk-not-a-reference"}},
        headers=admin,
    )
    assert literal.status_code == 400
    assert literal.json()["error"]["code"] == "key_not_reference"
    reference = client.put(
        "/api/v1/settings",
        json={"provider_key_refs": {"agentrouter": "env:CODEKAVACH_TEST_UNSET_KEY"}},
        headers=admin,
    )
    assert reference.status_code == 200
    providers = {item["id"]: item for item in client.get("/api/v1/providers", headers=admin).json()}
    assert providers["agentrouter"]["key_refs"] == ["env:CODEKAVACH_TEST_UNSET_KEY"]
    assert providers["agentrouter"]["configured"] is False
    assert providers["agentrouter"]["local"] is False
    assert json.dumps(client.get("/api/v1/providers", headers=admin).json())


def test_cancel_a_queued_scan(server: tuple[TestClient, Any], admin: dict[str, str]) -> None:
    client, state = server
    projects = client.get("/api/v1/projects", headers=admin).json()
    sample = next(item for item in projects if item["source"]["type"] == "sample")
    created = client.post(
        f"/api/v1/projects/{sample['id']}/scans", json={"provider": "mock"}, headers=admin
    ).json()
    cancelled = client.post(f"/api/v1/scans/{created['id']}/cancel", headers=admin)
    assert cancelled.status_code == 200
    state.runner.wait(created["id"], timeout=300)
    # The runner can return before the job thread records the final status (seen on macOS CI).
    deadline = time.time() + 30
    final = client.get(f"/api/v1/scans/{created['id']}", headers=admin).json()
    while final["status"] == "queued" and time.time() < deadline:
        time.sleep(0.2)
        final = client.get(f"/api/v1/scans/{created['id']}", headers=admin).json()
    assert final["status"] == "cancelled"


def test_a_job_cancelled_before_it_starts_records_cancelled(
    server: tuple[TestClient, Any], admin: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The race behind a flaky CI run: the cancel came after a worker took the job, so the runner
    # could not cancel the future, and the job used to return with the scan left "queued".
    client, state = server
    monkeypatch.setattr(state.runner, "submit", lambda scan_id: None)
    projects = client.get("/api/v1/projects", headers=admin).json()
    sample = next(item for item in projects if item["source"]["type"] == "sample")
    created = client.post(
        f"/api/v1/projects/{sample['id']}/scans", json={"provider": "mock"}, headers=admin
    ).json()
    assert created["status"] == "queued"
    token = CancellationToken()
    token.cancel("cancelled")
    execute_scan(ScanJob(scan_id=created["id"], state=state, token=token))
    final = client.get(f"/api/v1/scans/{created['id']}", headers=admin).json()
    assert final["status"] == "cancelled"
    assert final["finished_at"]
    done = [event for event in _events(client, created["id"], admin) if event["type"] == "done"]
    assert [event["data"]["status"] for event in done] == ["cancelled"]


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _events(client: TestClient, scan_id: str, headers: dict[str, str]) -> list[dict[str, Any]]:
    response = client.get(f"/api/v1/scans/{scan_id}/log", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    return list(body if isinstance(body, list) else body.get("events", []))


def _finish(client: TestClient, state: Any, scan_id: str, headers: dict[str, str]) -> Any:
    state.runner.wait(scan_id, timeout=300)
    deadline = time.time() + 60
    body: dict[str, Any] = {}
    while time.time() < deadline:
        body = client.get(f"/api/v1/scans/{scan_id}", headers=headers).json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            break
        time.sleep(0.2)
    return body


def test_verdicts_stream_live_most_severe_first(
    server: tuple[TestClient, Any], scan: dict[str, Any], admin: dict[str, str]
) -> None:
    client = server[0]
    events = _events(client, scan["id"], admin)
    findings = [e for e in events if e["type"] == "finding"]
    live = [e["data"] for e in findings if e["data"].get("phase") == "verdict"]
    final = [e["data"] for e in findings if e["data"].get("phase") != "verdict"]
    assert live and final
    # every live verdict arrives before the first rated finding, in review order
    first_final = next(i for i, e in enumerate(findings) if e["data"].get("phase") != "verdict")
    assert all(e["data"].get("phase") == "verdict" for e in findings[:first_final])
    ranks = [SEVERITY_RANK[item["severity"]] for item in live]
    assert ranks == sorted(ranks, reverse=True)
    assert {item["verdict"] for item in live} <= {"vulnerable", "not_vulnerable", "undecided"}
    reviewed = {cid for item in final for cid in item["candidate_ids"]}
    assert {item["id"] for item in live} <= reviewed


def test_a_quick_review_then_an_on_demand_review_of_one_finding(
    server: tuple[TestClient, Any],
    scan: dict[str, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
) -> None:
    client, state = server
    full = client.get(f"/api/v1/scans/{scan['id']}/findings", headers=admin).json()
    reviewed_before = {item["fingerprint"] for item in full if item["llm_reviewed"]}
    projects = client.get("/api/v1/projects", headers=admin).json()
    sample = next(item for item in projects if item["source"]["type"] == "sample")
    created = client.post(
        f"/api/v1/projects/{sample['id']}/scans",
        json={"privacy_level": "L2", "provider": "mock", "send": True, "review_limit": 1},
        headers=admin,
    )
    assert created.status_code == 201, created.text
    quick = _finish(client, state, created.json()["id"], admin)
    assert quick["status"] == "completed", quick
    findings = client.get(f"/api/v1/scans/{quick['id']}/findings", headers=admin).json()
    assert sum(1 for item in findings if item["llm_reviewed"]) == 1
    messages = [
        str((e.get("data") or e).get("message", ""))
        for e in _events(client, quick["id"], admin)
        if e.get("type") == "log"
    ]
    limited = [m for m in messages if "review limit" in m]
    assert len(limited) == 1, limited  # one summary line, not one per candidate
    assert not [m for m in messages if "cand_" in m]  # item failures are counted, not listed
    target = next(
        item
        for item in findings
        if not item["llm_reviewed"] and item["fingerprint"] in reviewed_before
    )
    url = f"/api/v1/findings/{target['id']}/review"
    assert client.post(url, headers=users["developer"]).status_code == 403
    answered = client.post(url, json={}, headers=users["auditor"])
    assert answered.status_code == 200, answered.text
    detail = answered.json()
    assert detail["id"] == target["id"]
    assert detail["llm_reviewed"] is True
    assert detail["llm_verdict"]["provider"] == "mock"
    assert detail["history"][-1]["action"] == "llm_review"
    again = client.get(f"/api/v1/scans/{quick['id']}/findings", headers=admin).json()
    assert sum(1 for item in again if item["llm_reviewed"]) == 2
    # The review's payload is listed with the scan's ledger, so "What the LLM saw" can open it.
    seq = next(r["ledger_seq"] for r in detail["provenance"]["llm_reviews"] if r.get("ledger_seq"))
    entry = client.get(f"/api/v1/scans/{quick['id']}/ledger/{seq}", headers=admin)
    assert entry.status_code == 200, entry.text
    assert entry.json()["entry"]["seq"] == seq
    missing = client.post("/api/v1/findings/nope/review", headers=users["auditor"])
    assert missing.status_code == 404
