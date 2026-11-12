"""The dashboard additions of the REST API, end to end with FastAPI's TestClient.

One module-scoped server scans the KavachBank sample with the mock provider through the real
pipeline at L3; the cases read the extra fields the approved dashboard design needs (scan mode and
engines, SSE counts and the egress event, ledger bytes, paging and exports, finding baseline,
engines, SLA and runs, saved views, statistics, privacy, policy, providers, evaluation, admin and
settings) and check the role of every new route.
"""

import json
import shutil
import sys
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


def test_sync_github_dry_run_without_a_token(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    scan: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = server[0]
    monkeypatch.delenv("CK_TEST_UNSET_GITHUB_TOKEN", raising=False)
    url = f"{API}/scans/{scan['id']}/sync/github"
    body = {"repo": "example/repo", "token_ref": "env:CK_TEST_UNSET_GITHUB_TOKEN", "dry_run": True}
    preview = client.post(url, json=body, headers=admin)
    assert preview.status_code == 200, preview.text
    assert preview.json()["notes"][0].startswith("env:CK_TEST_UNSET_GITHUB_TOKEN is not set")
    applied = client.post(url, json={**body, "dry_run": False}, headers=admin)
    assert applied.status_code == 400
    assert applied.json()["error"]["code"] == "token_unresolved"


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


def test_project_inventory_before_the_first_scan(
    server: tuple[TestClient, Any], admin: dict[str, str]
) -> None:
    client = server[0]
    body = {"name": "Inventory sample", "source": {"type": "sample"}}
    project = client.post(f"{API}/projects", json=body, headers=admin).json()
    found = client.get(f"{API}/projects/{project['id']}/inventory", headers=admin).json()
    assert found["scan_id"] is None
    assert found["totals"]["files"] > 0
    assert any(row["language"] == "python" for row in found["languages"])
    upload = {"name": "Inventory upload", "source": {"type": "upload"}}
    project = client.post(f"{API}/projects", json=upload, headers=admin).json()
    empty = client.get(f"{API}/projects/{project['id']}/inventory", headers=admin).json()
    assert empty["languages"] == [] and empty["totals"] is None


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


# --- policy, budgets, providers -------------------------------------------------------------

DRAFT = 'policy_version = 1\n[[path]]\npattern = "services/**"\nlevel = "L4"\n'


def test_policy_explain(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    url = f"{API}/policy/explain"
    body = client.get(url, params={"path": "services/api/accounts.py"}, headers=admin).json()
    assert body["in_inventory"] is True
    assert body["language"] == "python"
    assert body["level"] in {"L1", "L2", "L3", "L4"}
    assert sum(1 for item in body["contributions"] if item["winner"]) == 1
    assert body["explanation"].startswith("services/api/accounts.py")
    secret = client.get(url, params={"path": "config/secrets/key.yaml"}, headers=admin).json()
    assert secret["never_send"] is True and secret["decided_by"] == "never_send"
    assert client.get(url, params={"path": "../etc/passwd"}, headers=admin).status_code == 400
    assert client.get(url, params={"path": "a.py"}, headers=users["viewer"]).status_code == 403


def test_policy_validate_and_templates(
    server: tuple[TestClient, Any], users: dict[str, dict[str, str]], scan: dict[str, Any]
) -> None:
    client = server[0]
    viewer = users["viewer"]
    good = client.post(f"{API}/policy/validate", json={"toml": DRAFT}, headers=viewer).json()
    assert good["valid"] is True
    assert good["files_resolved"] == scan["files"]
    assert 0 < good["matches"]["path[0]"] <= good["files_resolved"]
    assert good["levels"].get("L4") == good["matches"]["path[0]"]
    bad_text = DRAFT.replace('"L4"', '"L9"')
    bad = client.post(f"{API}/policy/validate", json={"toml": bad_text}, headers=viewer).json()
    assert bad["valid"] is False
    assert bad["errors"][0]["code"].startswith("CK-POL-")
    assert bad["errors"][0]["line"] == 4
    found = client.get(f"{API}/policy/templates", headers=viewer).json()
    assert found[0]["id"] == "server-default" and found[0]["editor"] is True
    assert any(item["source"].startswith("docs/examples/") for item in found)
    assert all({"kind", "toml", "editor"} <= set(item) for item in found)


def test_privacy_budgets(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    body = client.get(f"{API}/privacy/budgets", params={"scan_id": scan["id"]},
                      headers=admin).json()  # fmt: skip
    rows = {row["id"]: row for row in body["budgets"]}
    assert rows["scan_disclosure"]["limit"] > 0
    assert rows["scan_disclosure"]["used"] is not None
    assert rows["input_tokens"]["used"] > 0
    assert client.get(f"{API}/privacy/budgets", headers=users["viewer"]).status_code == 403


def test_providers_wire_keys_and_usage(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    rows = {row["id"]: row for row in client.get(f"{API}/providers", headers=admin).json()}
    assert rows["mock"]["wire"] == "in process (no network)"
    router = rows["agentrouter"]
    assert router["wire"] == "OpenAI Responses API"
    assert router["key_ref_status"][0]["ref"].startswith("env:")
    assert router["key_ref_status"][0]["state"] in {"set", "not-set"}
    assert router["endpoint"].startswith("https://")
    usage = client.get(f"{API}/providers/usage", headers=admin).json()["usage"]
    mock = next(row for row in usage if row["provider"] == "mock")
    assert mock["requests"] > 0 and mock["input_tokens"] > 0
    month = mock["month"]
    assert client.get(f"{API}/providers/usage", params={"month": "1999-01"},
                      headers=admin).json()["usage"] == []  # fmt: skip
    assert client.get(f"{API}/providers/usage", params={"month": month},
                      headers=admin).json()["usage"]  # fmt: skip
    assert client.get(f"{API}/providers/usage", params={"month": "May"},
                      headers=admin).status_code == 400  # fmt: skip
    assert client.get(f"{API}/providers/usage", headers=users["viewer"]).status_code == 403


# --- evaluation -----------------------------------------------------------------------------


def test_evaluation_reads_the_latest_results(
    server: tuple[TestClient, Any], users: dict[str, dict[str, str]]
) -> None:
    client, state = server
    # The server is shared by the module and pytest-randomly may run the evaluation job test first.
    shutil.rmtree(state.config.data_dir / "evaluation", ignore_errors=True)
    empty = client.get(f"{API}/evaluation", headers=users["viewer"]).json()
    assert empty["available"] is False and empty["benchmarks"] == []
    root = state.config.data_dir / "evaluation" / "manual"
    (root / "detection").mkdir(parents=True)
    (root / "leakage").mkdir(parents=True)
    detection = {
        "kind": "detection",
        "dataset": {"name": "kavachbank"},
        "arms": [{"arm": "mock@L3", "level": "L3", "provider": "mock", "findings": 9,
                  "overall": {"precision": 0.9, "recall": 0.8, "f1": 0.85,
                              "f1_ci": [0.7, 0.95], "tp": 8, "fp": 1, "fn": 2}}],
    }  # fmt: skip
    leakage = {
        "kind": "leakage",
        "dataset": {"name": "kavachbank"},
        "levels": {"L3": {"canary": {"passed": True}, "identifier": {"subword_rate": 0.1},
                          "leakage_score": 12.0}},
        "frontier": [{"level": "L3", "privacy_score": 88.0, "leakage_score": 12.0, "f1": 0.85}],
        "zero_leak": True,
    }  # fmt: skip
    (root / "detection" / "results.json").write_text(json.dumps(detection), encoding="utf-8")
    (root / "leakage" / "results.json").write_text(json.dumps(leakage), encoding="utf-8")
    body = client.get(f"{API}/evaluation", headers=users["viewer"]).json()
    assert body["available"] is True and body["sample"] is False
    assert body["benchmarks"][0]["f1"] == 0.85
    assert body["benchmarks"][0]["f1_ci"] == [0.7, 0.95]
    assert body["frontier"][0]["level"] == "L3"
    canary = next(row for row in body["attacks"] if row["experiment"] == "canary")
    assert canary["by_level"]["L3"] is True
    assert body["zero_leak"] is True


def test_evaluation_run_starts_a_background_job(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codekavach.server.routers import evaluation  # noqa: PLC0415

    client = server[0]

    def fake_command(kind: str, dataset: Any, levels: list[str], out: Any, limit: Any) -> list[str]:
        script = (
            "import json, pathlib, sys; out = pathlib.Path(sys.argv[1]); "
            "out.mkdir(parents=True, exist_ok=True); "
            "(out / 'results.json').write_text(json.dumps({'kind': sys.argv[2], 'arms': []}))"
        )
        return [sys.executable, "-c", script, str(out), kind]

    monkeypatch.setattr(evaluation, "_command", fake_command)
    denied = client.post(f"{API}/evaluation/run", json={}, headers=users["auditor"])
    assert denied.status_code == 403
    started = client.post(f"{API}/evaluation/run", json={"levels": ["L3"]}, headers=admin)
    assert started.status_code == 202, started.text
    job = started.json()
    assert job["provider"] == "mock" and job["levels"] == ["L3"]
    for thread in list(evaluation._running.values()):
        thread.join(timeout=60)
    done = client.get(f"{API}/evaluation/runs/{job['id']}", headers=admin).json()
    assert done["status"] == "completed", done
    assert [step["status"] for step in done["steps"]] == ["completed", "completed"]
    latest = client.get(f"{API}/evaluation", headers=admin).json()
    assert latest["job"]["id"] == job["id"]
    assert client.get(f"{API}/evaluation/runs/eval_none", headers=admin).status_code == 404


# --- administration -------------------------------------------------------------------------


def test_role_change_and_revoke(
    server: tuple[TestClient, Any], admin: dict[str, str], users: dict[str, dict[str, str]]
) -> None:
    client, state = server
    body = {"username": "temp2", "password": "temp-password", "role": "viewer"}
    user = client.post(f"{API}/users", json=body, headers=admin).json()
    headers = _login(client, "temp2", "temp-password")
    changed = client.put(f"{API}/users/{user['id']}/role", json={"role": "developer"},
                         headers=admin)  # fmt: skip
    assert changed.status_code == 200 and changed.json()["role"] == "developer"
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401
    assert client.put(f"{API}/users/{user['id']}/role", json={"role": "root"},
                      headers=admin).status_code == 422  # fmt: skip
    assert client.put(f"{API}/users/{user['id']}/role", json={"role": "admin"},
                      headers=users["developer"]).status_code == 403  # fmt: skip
    headers = _login(client, "temp2", "temp-password")
    revoked = client.post(f"{API}/users/{user['id']}/revoke", headers=admin)
    assert revoked.status_code == 200 and revoked.json()["active"] is False
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401
    me = client.get(f"{API}/auth/me", headers=admin).json()
    assert client.post(f"{API}/users/{me['id']}/revoke", headers=admin).status_code == 409
    audit.flush(state.db)
    log = client.get(f"{API}/audit", params={"action": "user."}, headers=admin).json()
    assert {"user.role", "user.revoke"} <= {event["action"] for event in log["events"]}


def test_personal_tokens(
    server: tuple[TestClient, Any], admin: dict[str, str], users: dict[str, dict[str, str]]
) -> None:
    client = server[0]
    developer = users["developer"]
    created = client.post(f"{API}/me/tokens", json={"name": "ci", "expires_in_days": 30},
                          headers=developer)  # fmt: skip
    assert created.status_code == 201, created.text
    token = created.json()
    assert token["token"].startswith("ck_pat_")
    assert token["prefix"] == token["token"][: len(token["prefix"])]
    bearer = {"Authorization": f"Bearer {token['token']}"}
    assert client.get(f"{API}/auth/me", headers=bearer).json()["username"] == "developer2"
    assert client.get(f"{API}/users", headers=bearer).status_code == 403
    listed = client.get(f"{API}/me/tokens", headers=developer).json()
    assert [item["id"] for item in listed] == [token["id"]]
    assert "token" not in listed[0] and "token_hash" not in listed[0]
    assert listed[0]["last_used_at"] is not None
    every = client.get(f"{API}/tokens", headers=admin).json()
    assert any(item["id"] == token["id"] and item["username"] == "developer2" for item in every)
    assert client.get(f"{API}/tokens", headers=developer).status_code == 403
    assert client.delete(f"{API}/me/tokens/{token['id']}", headers=users["viewer"]).status_code \
        == 404  # fmt: skip
    assert client.delete(f"{API}/me/tokens/{token['id']}", headers=developer).status_code == 200
    assert client.get(f"{API}/auth/me", headers=bearer).status_code == 401
    second = client.post(f"{API}/me/tokens", json={"name": "other"}, headers=developer).json()
    assert client.delete(f"{API}/tokens/{second['id']}", headers=admin).status_code == 200
    gone = {"Authorization": f"Bearer {second['token']}"}
    assert client.get(f"{API}/auth/me", headers=gone).status_code == 401


def test_audit_paging_and_filters(
    server: tuple[TestClient, Any], admin: dict[str, str], users: dict[str, dict[str, str]]
) -> None:
    client, state = server
    audit.flush(state.db)
    page = client.get(f"{API}/audit", params={"limit": 2}, headers=users["auditor"]).json()
    assert page["chain_intact"] is True
    assert len(page["events"]) == 2 and page["total"] > 2
    nxt = client.get(f"{API}/audit", params={"limit": 2, "offset": 2},
                     headers=users["auditor"]).json()  # fmt: skip
    assert nxt["events"][0]["id"] < page["events"][-1]["id"]
    denied = client.get(f"{API}/audit", params={"outcome": "denied"}, headers=admin).json()
    assert all(event["outcome"] == "denied" for event in denied["events"])
    assert client.get(f"{API}/audit", headers=users["developer"]).status_code == 403


def test_vault_and_retention_status(
    server: tuple[TestClient, Any],
    admin: dict[str, str],
    users: dict[str, dict[str, str]],
    scan: dict[str, Any],
) -> None:
    client = server[0]
    body = client.get(f"{API}/vault", headers=admin).json()
    assert body["count"] >= 1
    row = next(item for item in body["vaults"] if item["scan_id"] == scan["id"])
    assert row["records"] > 0
    assert set(row) <= {
        "scan_id",
        "project_id",
        "format_version",
        "key_source",
        "records",
        "created_at",
        "last_write_at",
        "rotated_at",
        "rotations",
        "size_bytes",
    }
    text = json.dumps(body)
    assert "fn_" not in text and "var_" not in text
    assert client.get(f"{API}/vault", headers=users["auditor"]).status_code == 403
    kept = client.get(f"{API}/retention", headers=admin).json()
    assert kept["scans"] >= 1 and kept["scans_bytes"] > 0
    assert kept["automatic_purge"] is False


def test_not_implemented_features_answer_501(
    server: tuple[TestClient, Any], admin: dict[str, str]
) -> None:
    client = server[0]
    for url in (f"{API}/orgs", f"{API}/auth/sso"):
        response = client.get(url, headers=admin)
        assert response.status_code == 501
        assert response.json()["error"]["code"] == "not_implemented"


# --- the caller's settings ------------------------------------------------------------------


def test_profile_preferences_and_notifications(
    server: tuple[TestClient, Any], users: dict[str, dict[str, str]], scan: dict[str, Any]
) -> None:
    client = server[0]
    viewer = users["viewer"]
    updated = client.patch(f"{API}/me", json={"display_name": "Vee Ewer", "email": "v@example.org"},
                           headers=viewer)  # fmt: skip
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "Vee Ewer"
    prefs = client.patch(f"{API}/me/preferences", json={"density": "compact",
                         "time_zone": "Australia/Sydney"}, headers=viewer).json()  # fmt: skip
    assert prefs["density"] == "compact" and prefs["theme"] == "system"
    assert client.get(f"{API}/me", headers=viewer).json()["preferences"]["density"] == "compact"
    bad = client.patch(f"{API}/me/preferences", json={"time_zone": "Mars/Base"}, headers=viewer)
    assert bad.status_code == 400
    assert client.patch(f"{API}/me/preferences", json={"colour": "red"},
                        headers=viewer).status_code == 422  # fmt: skip
    notes = client.patch(f"{API}/me/notifications",
                         json={"events": {"scan_completed": {"email": True}}},
                         headers=viewer).json()  # fmt: skip
    assert notes["events"]["scan_completed"] == {"in_app": True, "email": True}
    assert "stored only" in notes["delivery"]
    assert client.patch(f"{API}/me/notifications", json={"events": {"nope": {"email": True}}},
                        headers=viewer).status_code == 400  # fmt: skip
    feed = client.get(f"{API}/notifications", headers=viewer).json()
    assert any(item["event"] == "scan_completed" for item in feed["items"])
    assert feed["unread"] >= 1
    client.post(f"{API}/notifications/read", headers=viewer)
    assert client.get(f"{API}/notifications", headers=viewer).json()["unread"] == 0


def test_openapi_lists_the_new_routes(server: tuple[TestClient, Any]) -> None:
    paths = server[0].get("/api/openapi.json").json()["paths"]
    for route in (
        "/api/v1/findings",
        "/api/v1/views",
        "/api/v1/engines",
        "/api/v1/projects/{project_id}/inventory",
        "/api/v1/system/health",
        "/api/v1/privacy/invariants",
        "/api/v1/privacy/budgets",
        "/api/v1/policy/explain",
        "/api/v1/policy/validate",
        "/api/v1/policy/templates",
        "/api/v1/providers/usage",
        "/api/v1/evaluation",
        "/api/v1/evaluation/run",
        "/api/v1/users/{user_id}/role",
        "/api/v1/users/{user_id}/revoke",
        "/api/v1/tokens",
        "/api/v1/me/tokens",
        "/api/v1/me/preferences",
        "/api/v1/me/notifications",
        "/api/v1/notifications",
        "/api/v1/vault",
        "/api/v1/retention",
        "/api/v1/scans/{scan_id}/ledger-verification",
        "/api/v1/scans/{scan_id}/privacy/attestation.{fmt}",
    ):
        assert route in paths, route
