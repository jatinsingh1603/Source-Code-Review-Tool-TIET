"""Account lifecycle of the REST API: e-mail checks, the caller's own password, vault key origin."""

from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from codekavach.server.app import create_app
from codekavach.server.config import VAULT_PASSPHRASE_ENV, ServerConfig
from tests.support.server import ADMIN_PASSWORD

API = "/api/v1"


def _login(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture
def server(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[TestClient, dict[str, str]]]:
    monkeypatch.delenv(VAULT_PASSPHRASE_ENV, raising=False)
    config = ServerConfig(
        data_dir=tmp_path, ui_dir=None, workers=1, admin_password=ADMIN_PASSWORD,
        force_password_change=False,
        login_attempts_per_minute=1000,
    )  # fmt: skip
    with TestClient(create_app(config)) as client:
        yield client, _login(client, "admin", ADMIN_PASSWORD)


def test_user_email_must_look_like_an_address(server: tuple[TestClient, dict[str, str]]) -> None:
    client, admin = server
    # pragma: allowlist nextline secret
    body = {"username": "priya", "password": "long-enough-1", "email": "not-an-email"}
    assert client.post(f"{API}/users", json=body, headers=admin).status_code == 422
    body["email"] = "priya@example.edu"
    created = client.post(f"{API}/users", json=body, headers=admin)
    assert created.status_code == 201
    user_id = created.json()["id"]
    bad = client.patch(f"{API}/users/{user_id}", json={"email": "x@y"}, headers=admin)
    assert bad.status_code == 422
    cleared = client.patch(f"{API}/users/{user_id}", json={"email": ""}, headers=admin)
    assert cleared.status_code == 200


def test_change_own_password_keeps_this_session_and_ends_the_others(
    server: tuple[TestClient, dict[str, str]],
) -> None:
    client, admin = server
    # pragma: allowlist nextline secret
    body = {"username": "dev1", "password": "first-password", "role": "developer"}
    assert client.post(f"{API}/users", json=body, headers=admin).status_code == 201
    mine = _login(client, "dev1", "first-password")
    other = _login(client, "dev1", "first-password")
    # pragma: allowlist nextline secret
    wrong = {"current_password": "nope", "new_password": "second-password"}
    response = client.post(f"{API}/me/password", json=wrong, headers=mine)
    assert response.status_code == 400
    assert "current password" in response.json()["error"]["message"]
    # pragma: allowlist nextline secret
    short = {"current_password": "first-password", "new_password": "short"}
    assert client.post(f"{API}/me/password", json=short, headers=mine).status_code == 422
    # pragma: allowlist nextline secret
    good = {"current_password": "first-password", "new_password": "second-password"}
    assert client.post(f"{API}/me/password", json=good, headers=mine).status_code == 200
    assert client.get(f"{API}/auth/me", headers=mine).status_code == 200
    assert client.get(f"{API}/auth/me", headers=other).status_code == 401
    old = client.post(f"{API}/auth/login", json={"username": "dev1", "password": "first-password"})
    assert old.status_code == 401
    _login(client, "dev1", "second-password")


def test_vault_key_origin_names_a_generated_file(server: tuple[TestClient, dict[str, str]]) -> None:
    client, admin = server
    vault = client.get(f"{API}/vault", headers=admin).json()
    assert vault["key_source"] == "passphrase (server-generated file, mode 0600)"


def test_vault_key_origin_names_the_environment_variable(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(VAULT_PASSPHRASE_ENV, "a passphrase the operator chose")
    config = ServerConfig(
        data_dir=tmp_path,
        ui_dir=None,
        workers=1,
        admin_password=ADMIN_PASSWORD,
        force_password_change=False,
    )
    with TestClient(create_app(config)) as client:
        admin = _login(client, "admin", ADMIN_PASSWORD)
        vault = client.get(f"{API}/vault", headers=admin).json()
    assert vault["key_source"] == "passphrase (environment variable)"


def test_organisation_name_cannot_be_blank(server: tuple[TestClient, dict[str, str]]) -> None:
    client, admin = server
    assert client.put(f"{API}/settings", json={"org_name": "   "}, headers=admin).status_code == 422
    saved = client.put(f"{API}/settings", json={"org_name": "  Thapar CSED  "}, headers=admin)
    assert saved.status_code == 200, saved.text
    assert client.get(f"{API}/settings", headers=admin).json()["org_name"] == "Thapar CSED"


def test_usernames_are_unique_whatever_their_case(
    server: tuple[TestClient, dict[str, str]],
) -> None:
    client, admin = server
    # pragma: allowlist nextline secret
    body = {"username": "ADMIN", "password": "long-enough-1", "role": "admin"}
    response = client.post(f"{API}/users", json=body, headers=admin)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "user_exists"
    body["username"] = "Asha"
    assert client.post(f"{API}/users", json=body, headers=admin).status_code == 201
    body["username"] = "asha"
    assert client.post(f"{API}/users", json=body, headers=admin).status_code == 409


def test_a_chunked_body_past_the_limit_is_refused(tmp_path: Any) -> None:
    """A body without Content-Length is counted as it arrives, not read whole."""
    config = ServerConfig(
        data_dir=tmp_path, ui_dir=None, workers=1, admin_password=ADMIN_PASSWORD,
        force_password_change=False,
        max_upload_bytes=1024, seed=False,
    )  # fmt: skip

    def chunks() -> Iterator[bytes]:
        yield b'{"username": "'
        for _ in range(3):
            yield b"a" * (512 * 1024)
        yield b'", "password": "x"}'

    with TestClient(create_app(config)) as client:
        headers = {"Content-Type": "application/json"}
        response = client.post(f"{API}/auth/login", content=chunks(), headers=headers)
        assert "content-length" not in response.request.headers
        assert response.status_code == 413, response.text
        assert response.json()["detail"] == "request body too large"
        small = client.post(f"{API}/auth/login", content=iter([b"{}"]), headers=headers)
        assert small.status_code == 422
