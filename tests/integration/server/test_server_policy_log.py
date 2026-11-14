"""The scan log says how many candidates a never-send policy rule kept from the model."""

import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from codekavach.server.app import create_app
from codekavach.server.config import ServerConfig

API = "/api/v1"
POLICY = 'policy_version = 1\n\n[[path]]\npattern = "services/web/**"\nnever_send = true\n'


def _scan(client: TestClient, headers: dict[str, str]) -> list[str]:
    projects = client.get(f"{API}/projects", headers=headers).json()
    sample = next(item for item in projects if item["source"]["type"] == "sample")
    created = client.post(
        f"{API}/projects/{sample['id']}/scans",
        json={"privacy_level": "L3", "provider": "mock", "send": True},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]
    client.app.state.server.runner.wait(scan_id, timeout=300)  # type: ignore[attr-defined]
    deadline = time.time() + 60
    while time.time() < deadline:
        if client.get(f"{API}/scans/{scan_id}", headers=headers).json()["status"] == "completed":
            break
        time.sleep(0.2)
    events: list[dict[str, Any]] = client.get(f"{API}/scans/{scan_id}/log", headers=headers).json()
    return [str(event["data"].get("message", "")) for event in events]


def test_never_send_candidates_are_named_in_the_scan_log(tmp_path: Path) -> None:
    config = ServerConfig(data_dir=tmp_path, ui_dir=None, workers=1, admin_password="kavach-admin")
    with TestClient(create_app(config)) as client:
        reply = client.post(
            f"{API}/auth/login", json={"username": "admin", "password": "kavach-admin"}
        )
        headers = {"Authorization": f"Bearer {reply.json()['token']}"}
        before = _scan(client, headers)
        assert not [m for m in before if "privacy policy keeps their files local" in m]
        saved = client.put(f"{API}/policy", json={"toml": POLICY}, headers=headers)
        assert saved.status_code == 200, saved.text
        after = _scan(client, headers)
        kept = [m for m in after if "privacy policy keeps their files local" in m]
        assert len(kept) == 1 and kept[0].split()[0].isdigit() and int(kept[0].split()[0]) > 0
