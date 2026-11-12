"""The dashboard additions of the REST API, end to end with FastAPI's TestClient.

One module-scoped server scans the KavachBank sample with the mock provider through the real
pipeline at L3; the cases read the extra fields the approved dashboard design needs (scan mode and
engines, SSE counts and the egress event, ledger bytes, paging and exports, finding baseline,
engines, SLA and runs, saved views, statistics, privacy, policy, providers, evaluation, admin and
settings) and check the role of every new route.
"""

import json
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from codekavach.server import audit
from codekavach.server.app import create_app
from codekavach.server.config import ServerConfig

pytest.importorskip("fastapi")

ADMIN = {"username": "admin", "password": "kavach-admin"}
API = "/api/v1"


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[TestClient, Any]]:
    data = tmp_path_factory.mktemp("server-dashboard")
    config = ServerConfig(
        data_dir=data, ui_dir=None, workers=1, admin_password="kavach-admin",
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
        body = {"username": f"{role}2", "password": f"{role}-password", "role": role}
        response = client.post(f"{API}/users", json=body, headers=admin)
        assert response.status_code == 201, response.text
        headers[role] = _login(client, f"{role}2", f"{role}-password")
    return headers


@pytest.fixture(scope="module")
def scan(server: tuple[TestClient, Any], admin: dict[str, str]) -> dict[str, Any]:
    client, state = server
    projects = client.get(f"{API}/projects", headers=admin).json()
    sample = next(item for item in projects if item["source"]["type"] == "sample")
    created = client.post(
        f"{API}/projects/{sample['id']}/scans",
        json={"privacy_level": "L3", "provider": "mock", "send": True},
        headers=admin,
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]
    state.runner.wait(scan_id, timeout=300)
    deadline = time.time() + 60
    body: dict[str, Any] = {}
    while time.time() < deadline:
        body = client.get(f"{API}/scans/{scan_id}", headers=admin).json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            break
        time.sleep(0.2)
    assert body["status"] == "completed", body
    return dict(body)


def _reviewed(client: TestClient, admin: dict[str, str]) -> dict[str, Any]:
    page = client.get(f"{API}/findings", params={"verdict": "vulnerable", "limit": 1},
                      headers=admin).json()  # fmt: skip
    assert page["items"], page
    item: dict[str, Any] = page["items"][0]
    return item


# --- scans and events -----------------------------------------------------------------------


def test_scan_has_mode_ref_payloads_engines_and_eta(scan: dict[str, Any]) -> None:
    assert scan["mode"] == "full"
    assert "ref" in scan
    assert scan["payloads"] and scan["payloads"] > 0
    ids = {engine["id"] for engine in scan["engines"]}
    assert {"rules", "taint", "secrets"} <= ids
    assert scan["eta_seconds"] is None
    assert scan["duration_seconds"] is not None


def test_events_carry_counts_egress_and_timestamps(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    events = server[0].get(f"{API}/scans/{scan['id']}/log", headers=admin).json()
    stages = [event["data"] for event in events if event["type"] == "stage"]
    assert all("count" in data and "total" in data for data in stages)
    assert any(data["count"] for data in stages if data["status"] == "completed")
    egress = [event["data"] for event in events if event["type"] == "egress"]
    final = [data for data in egress if data.get("final")]
    assert final, egress
    assert final[-1]["bytes"] > 0
    assert final[-1]["terms_found"] == 0
    assert {"payloads", "secrets_checked", "terms_checked"} <= set(final[-1])
    assert all("at" in event["data"] for event in events if event["type"] == "log")


# --- privacy summary and ledger -------------------------------------------------------------


def test_privacy_summary_counts_bytes_and_lines(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    body = server[0].get(f"{API}/scans/{scan['id']}/privacy", headers=admin).json()
    assert body["bytes_sent"] > 0
    assert body["lines_sent"] > 0
    assert body["repo_bytes"] > body["bytes_sent"]
    assert body["score_parts"] and {"label", "value", "kind"} <= set(body["score_parts"][0])


def test_ledger_bytes_paging_search_and_export(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    url = f"{API}/scans/{scan['id']}/ledger"
    full = client.get(url, headers=admin).json()
    assert full["total"] == full["count"] > 2
    assert all(entry["bytes"] for entry in full["entries"] if entry["outcome"] == "sent")
    assert "payload_text" not in full["entries"][0]
    page = client.get(url, params={"offset": 1, "limit": 2}, headers=admin).json()
    assert page["count"] == 2
    assert page["entries"][0]["seq"] == full["entries"][1]["seq"]
    blocked = client.get(url, params={"outcome": "blocked"}, headers=admin).json()
    assert all(entry["outcome"] == "blocked" for entry in blocked["entries"])
    head = full["entries"][0]["entry_hash"][:12]
    assert client.get(url, params={"q": head}, headers=admin).json()["total"] == 1
    export = client.get(url, params={"format": "jsonl"}, headers=admin)
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("application/x-ndjson")
    lines = [json.loads(line) for line in export.text.splitlines()]
    assert len(lines) == full["total"]
    assert all("payload_text" not in line for line in lines)
    assert client.get(url, headers=users["viewer"]).status_code == 403


def test_ledger_entry_has_lines_path_and_bytes(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    client = server[0]
    entries = client.get(f"{API}/scans/{scan['id']}/ledger", headers=admin).json()["entries"]
    sent = next(entry for entry in entries if entry["outcome"] == "sent" and entry["candidate_id"])
    detail = client.get(f"{API}/scans/{scan['id']}/ledger/{sent['seq']}", headers=admin).json()
    assert detail["bytes"] == sent["bytes"]
    assert detail["lines_sent"] > 0
    assert detail["path"]
    assert detail["lines_total"] >= detail["lines_original"] > 0
    assert detail["slice_lines"]


def test_verify_and_verification_report(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    result = client.post(f"{API}/scans/{scan['id']}/ledger/verify", headers=admin).json()
    assert result["ok"] and result["chain_ok"]
    assert result["hashes_ok"] > 0
    assert result["terms_checked"] > 0
    assert result["terms_found"] == 0
    assert result["head_hash"]
    url = f"{API}/scans/{scan['id']}/ledger-verification"
    text = client.get(url, params={"format": "txt"}, headers=admin)
    assert text.status_code == 200
    assert "Result: PASS" in text.text
    assert "attachment" in text.headers["content-disposition"]
    assert json.loads(client.get(url, headers=admin).text)["ok"] is True
    assert client.get(url, headers=users["viewer"]).status_code == 403


def test_attestation_json(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client, state = server
    url = f"{API}/scans/{scan['id']}/privacy/attestation.json"
    response = client.get(url, headers=users["viewer"])
    assert response.status_code == 200
    body = json.loads(response.text)
    assert body["attestation"]["level"] == "L3"
    assert body["levels_used"].get("L3", 0) > 0
    assert len(body["digest"]) == 64
    assert body["ledger_head_hash"]
    assert client.get(f"{API}/scans/{scan['id']}/privacy/attestation.xml",
                      headers=admin).status_code == 404  # fmt: skip
    audit.flush(state.db)


# --- findings -------------------------------------------------------------------------------


def test_findings_paging_and_filters(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    client = server[0]
    first = client.get(f"{API}/findings", params={"limit": 5}, headers=admin).json()
    assert first["total"] == scan["findings_total"]
    assert len(first["items"]) == 5
    assert first["offset"] == 0 and first["limit"] == 5
    second = client.get(f"{API}/findings", params={"limit": 5, "offset": 5},
                        headers=admin).json()  # fmt: skip
    assert {item["id"] for item in first["items"]}.isdisjoint(
        {item["id"] for item in second["items"]}
    )
    python = client.get(f"{API}/findings", params={"language": "python", "limit": 500},
                        headers=admin).json()  # fmt: skip
    assert python["total"] > 0
    assert all(item["language"] == "python" for item in python["items"])
    injection = client.get(f"{API}/findings", params={"owasp": "A03", "limit": 500},
                           headers=admin).json()  # fmt: skip
    assert injection["total"] > 0
    assert injection["total"] < scan["findings_total"]
    assert any(item["owasp"].startswith("A03") for item in injection["items"])
    level = client.get(f"{API}/findings", params={"level": "L3"}, headers=admin).json()
    assert level["total"] == scan["findings_total"]
    unreviewed = client.get(f"{API}/findings", params={"verdict": "unreviewed"},
                            headers=admin).json()  # fmt: skip
    vulnerable = client.get(f"{API}/findings", params={"verdict": "vulnerable"},
                            headers=admin).json()  # fmt: skip
    assert unreviewed["total"] + vulnerable["total"] <= scan["findings_total"]
    engine = first["items"][0]["engines"][0]["engine"]
    by_engine = client.get(f"{API}/findings", params={"engine": engine, "limit": 500},
                           headers=admin).json()  # fmt: skip
    assert all(engine in {e["engine"] for e in item["engines"]} for item in by_engine["items"])
    listed = client.get(f"{API}/scans/{scan['id']}/findings", params={"limit": 3},
                        headers=admin)  # fmt: skip
    assert len(listed.json()) == 3
    assert listed.headers["X-Total-Count"] == str(scan["findings_total"])


def test_finding_engines_sla_runs_and_scenario(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    client = server[0]
    item = _reviewed(client, admin)
    assert item["sla_days"] is not None
    assert item["due_at"]
    assert item["sla_state"] in {"on_track", "due_soon", "overdue"}
    assert item["engines"] and item["merged_from"] == len(item["engines"])
    detail = client.get(f"{API}/findings/{item['id']}", headers=admin).json()
    runs = detail["llm"]["runs"]
    assert runs and runs[0]["source"] == "review"
    assert any(run["ledger_seq"] for run in runs)
    assert detail["llm"]["consensus"]["samples"] >= 1
    assert detail["baseline_state"] is None
    assert detail["verdict"] == "vulnerable"
    assert "remediation_diff" in detail
    merged = client.get(f"{API}/findings", params={"limit": 500}, headers=admin).json()
    assert any(engine["merged"] for row in merged["items"] for engine in row["engines"])


def test_sync_github_takes_finding_ids(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    client = server[0]
    body = {"repo": "example/repo", "dry_run": True, "finding_ids": ["find_not_here"]}
    response = client.post(f"{API}/scans/{scan['id']}/sync/github", json=body, headers=admin)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "finding_not_in_scan"


def test_saved_views(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    views = client.get(f"{API}/views", headers=users["viewer"]).json()
    by_id = {view["id"]: view for view in views}
    assert by_id["all"]["count"] == scan["findings_total"]
    assert by_id["mine"]["count"] == 0
    created = client.post(
        f"{API}/views", json={"name": "Python criticals",
                              "filters": {"language": "python", "severity": "critical"}},
        headers=users["viewer"],
    )  # fmt: skip
    assert created.status_code == 201, created.text
    view = created.json()
    assert view["count"] > 0
    page = client.get(f"{API}/findings", params={"view": view["id"]},
                      headers=users["viewer"]).json()  # fmt: skip
    assert page["total"] == view["count"]
    other = client.delete(f"{API}/views/{view['id']}", headers=users["developer"])
    assert other.status_code == 404
    assert client.delete(f"{API}/views/{view['id']}", headers=users["viewer"]).status_code == 200


def test_baseline_compares_with_the_previous_scan(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    client = server[0]
    page = client.get(f"{API}/findings", params={"scan_id": scan["id"], "baseline": scan["id"]},
                      headers=admin).json()  # fmt: skip
    assert page["baseline_scan_id"] is None
    assert all(item["baseline_state"] is None for item in page["items"])


# --- statistics, engines, inventory, health -------------------------------------------------


def test_stats_extras(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    item = _reviewed(client, admin)
    patch = {"status": "fixed", "comment": "patched"}
    assert client.patch(f"{API}/findings/{item['id']}", json=patch,
                        headers=admin).status_code == 200  # fmt: skip
    body = client.get(f"{API}/stats", headers=users["viewer"]).json()
    assert body["mttr_days"] is not None and body["mttr_days"] >= 0
    assert body["mttr_samples"] == 1
    assert "mttr_delta_days" in body
    assert all("info" in point for point in body["trend"])
    matrix = body["risk_matrix"]
    assert sum(cell["count"] for cell in matrix) == scan["findings_total"]
    assert all(1 <= cell["likelihood"] <= 5 and 1 <= cell["impact"] <= 5 for cell in matrix)
    assert body["risk_matrix_bands"]
    assert body["owasp_by_engine"]
    assert {"owasp", "engine", "count"} <= set(body["owasp_by_engine"][0])
    top = body["top_cwes"]
    assert top and top[0]["count"] >= top[-1]["count"]
    assert top[0]["cwe"].startswith("CWE-")
    client.patch(f"{API}/findings/{item['id']}", json={"status": "open"}, headers=admin)


def test_engines_list_install_status(
    server: tuple[TestClient, Any], users: dict[str, dict[str, str]]
) -> None:
    rows = server[0].get(f"{API}/engines", headers=users["viewer"]).json()
    builtin = [row for row in rows if row["kind"] == "builtin"]
    assert {row["id"] for row in builtin} >= {"rules", "taint", "secrets", "iac", "sca"}
    assert all(row["installed"] for row in builtin)
    external = [row for row in rows if row["kind"] == "external"]
    assert external
    assert all(isinstance(row["installed"], bool) and row["status"] for row in external)


def test_project_inventory(
    server: tuple[TestClient, Any], admin: dict[str, str], scan: dict[str, Any]
) -> None:
    client = server[0]
    body = client.get(f"{API}/projects/{scan['project_id']}/inventory", headers=admin).json()
    assert body["scan_id"] == scan["id"]
    python = next(row for row in body["languages"] if row["language"] == "python")
    assert python["files"] > 0 and python["lines"] > 0
    assert python["support"] == "full"
    assert body["totals"]["lines"] == sum(row["lines"] for row in body["languages"])
    assert client.get(f"{API}/projects/prj_missing/inventory", headers=admin).status_code == 404


def test_health_network_and_system_health(
    server: tuple[TestClient, Any], admin: dict[str, str], users: dict[str, dict[str, str]]
) -> None:
    client = server[0]
    assert client.get(f"{API}/health").json()["network"] == "offline"
    body = client.get(f"{API}/system/health", headers=admin).json()
    names = {check["name"] for check in body["checks"]}
    assert {"server:database", "server:disk", "server:vault_key"} <= names
    assert body["status"] in {"pass", "warn", "fail"}
    assert len(body["invariants"]["invariants"]) == 6
    assert client.get(f"{API}/system/health", headers=users["auditor"]).status_code == 403


def test_invariants_report_recorded_results(
    server: tuple[TestClient, Any], users: dict[str, dict[str, str]], scan: dict[str, Any]
) -> None:
    client, state = server
    url = f"{API}/privacy/invariants"
    before = client.get(url, headers=users["viewer"]).json()
    assert before["recorded"] is False
    by_id = {row["id"]: row for row in before["invariants"]}
    assert by_id["I1"]["status"] == "not_recorded"
    assert by_id["I6"]["guard"]["passed"] is True
    report = state.config.data_dir / "invariants" / "junit.xml"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        '<testsuites><testsuite name="pytest">'
        '<testcase classname="tests.privacy.test_i1_single_egress" name="test_a"/>'
        '<testcase classname="tests.privacy.test_vault_locality" name="test_b">'
        '<failure message="boom"/></testcase>'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    after = client.get(url, headers=users["viewer"]).json()
    assert after["recorded"] is True and after["run_at"]
    rows = {row["id"]: row for row in after["invariants"]}
    assert rows["I1"]["status"] == "passed"
    assert rows["I1"]["tests"]["passed"] == 1
    assert rows["I3"]["status"] == "failed"
    assert rows["I5"]["status"] == "not_recorded"
    report.unlink()
