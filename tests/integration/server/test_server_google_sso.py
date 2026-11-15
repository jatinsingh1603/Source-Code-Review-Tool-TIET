"""Google sign-in: off without configuration; the full flow with the token endpoint replaced."""

import base64
import json
import time
from collections.abc import Callable, Iterator, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from codekavach.server.app import create_app
from codekavach.server.auth import google
from codekavach.server.config import ServerConfig

API = "/api/v1"
CLIENT_ID = "test-client.apps.googleusercontent.com"
BASE = "http://testserver"


def _config(tmp_path: Any, sso: google.GoogleSso | None) -> ServerConfig:
    return ServerConfig(
        # pragma: allowlist nextline secret
        data_dir=tmp_path, ui_dir=None, workers=1, admin_password="kavach-admin",
        login_attempts_per_minute=1000, google=sso,
    )  # fmt: skip


def _sso(**changes: Any) -> google.GoogleSso:
    # pragma: allowlist nextline secret
    return google.GoogleSso(client_id=CLIENT_ID, client_secret="test-secret-value", **changes)


def _id_token(claims: Mapping[str, Any]) -> str:
    def part(value: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'RS256'})}.{part(claims)}.c2ln"


Flow = Callable[..., Any]


@pytest.fixture
def flow(tmp_path: Any) -> Iterator[Flow]:
    """``flow(sso, **claim changes)`` runs login and callback and returns the last response."""
    clients: list[TestClient] = []

    def run(
        sso: google.GoogleSso | None = None, *, state: str | None = None, **changes: Any
    ) -> Any:
        app = create_app(_config(tmp_path, sso or _sso()))
        base = (sso.public_url if sso else "") or BASE
        client = TestClient(app, base_url=base, follow_redirects=False)
        client.__enter__()
        clients.append(client)
        start = client.get(f"{API}/auth/google/login")
        assert start.status_code == 302
        query = parse_qs(urlsplit(start.headers["location"]).query)
        seen: dict[str, str] = {}

        def exchange(
            config: google.GoogleSso, code: str, verifier: str, callback: str
        ) -> Mapping[str, Any]:
            seen.update(code=code, verifier=verifier, callback=callback)
            claims = {
                "iss": "https://accounts.google.com",
                "aud": config.client_id,
                "exp": int(time.time()) + 300,
                "nonce": query["nonce"][0],
                "email": "Asha@Example.edu",
                "email_verified": True,
                "name": "Asha Rao",
            }
            claims.update(changes)
            return {"id_token": _id_token(claims)}

        app.state.google_exchange = exchange
        response = client.get(
            f"{API}/auth/google/callback",
            params={"code": "the-code", "state": state or query["state"][0]},
        )
        response.client = client  # type: ignore[attr-defined]
        response.seen = seen  # type: ignore[attr-defined]
        response.query = query  # type: ignore[attr-defined]
        return response

    yield run
    for client in clients:
        client.__exit__(None, None, None)


def test_off_without_configuration(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (google.CLIENT_ID_ENV, google.CLIENT_SECRET_ENV):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    config = ServerConfig(data_dir=tmp_path, ui_dir=None, workers=1)
    assert config.google is None
    with TestClient(create_app(config), follow_redirects=False) as client:
        assert client.get(f"{API}/auth/providers").json() == {"google": {"enabled": False}}
        assert client.get(f"{API}/auth/google/login").status_code == 404
        assert client.get(f"{API}/auth/google/callback?code=x&state=y").status_code == 404


def test_settings_come_from_the_environment(tmp_path: Any) -> None:
    secret_file = tmp_path / "secret"
    secret_file.write_text("from-a-file\n", encoding="utf-8")
    env = {
        google.CLIENT_ID_ENV: CLIENT_ID,
        f"{google.CLIENT_SECRET_ENV}_FILE": str(secret_file),
        google.ALLOWED_DOMAINS_ENV: "Example.edu, thapar.edu",
        google.ALLOWED_EMAILS_ENV: "guest@gmail.com",
        google.DEFAULT_ROLE_ENV: "superuser",
        google.PUBLIC_URL_ENV: "https://kavach.example.edu/",
    }
    sso = google.from_env(env)
    assert sso is not None
    assert sso.client_secret == "from-a-file"  # pragma: allowlist secret
    assert sso.default_role == "viewer"
    assert sso.public_url == "https://kavach.example.edu"
    assert sso.allows("x@thapar.edu") and sso.allows("Guest@gmail.com")
    assert not sso.allows("other@gmail.com")
    assert "from-a-file" not in repr(sso)
    assert google.from_env({google.CLIENT_ID_ENV: CLIENT_ID}) is None


def test_login_redirects_to_google_with_state_nonce_and_pkce(tmp_path: Any) -> None:
    with TestClient(create_app(_config(tmp_path, _sso())), follow_redirects=False) as client:
        assert client.get(f"{API}/auth/providers").json() == {"google": {"enabled": True}}
        response = client.get(f"{API}/auth/google/login")
    assert response.status_code == 302
    target = urlsplit(response.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == google.AUTH_URL
    query = {key: value[0] for key, value in parse_qs(target.query).items()}
    assert query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == f"{BASE}/api/v1/auth/google/callback"
    assert query["response_type"] == "code"
    assert query["scope"] == "openid email profile"
    assert query["code_challenge_method"] == "S256"
    assert query["prompt"] == "select_account"
    assert query["state"] and query["nonce"] and query["code_challenge"]
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "samesite=lax" in cookie.lower()
    assert "test-secret-value" not in response.headers["location"]


def test_happy_path_creates_a_viewer_and_issues_a_session_token(flow: Flow) -> None:
    response = flow()
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(f"{BASE}/login#sso_token=")
    assert "?" not in location
    assert response.seen["callback"] == f"{BASE}/api/v1/auth/google/callback"
    assert response.seen["code"] == "the-code"
    token = location.split("#sso_token=")[1]
    me = response.client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "asha@example.edu"
    assert body["display_name"] == "Asha Rao"
    assert body["role"] == "viewer"
    # The account has no usable local password.
    login = response.client.post(
        f"{API}/auth/login", json={"username": "asha@example.edu", "password": ""}
    )
    assert login.status_code in {401, 422}


def test_public_url_and_default_role_are_used(flow: Flow) -> None:
    sso = _sso(public_url="https://kavach.example.edu", default_role="developer")
    response = flow(sso)
    assert response.query["redirect_uri"][0] == (
        "https://kavach.example.edu/api/v1/auth/google/callback"
    )
    assert response.headers["location"].startswith("https://kavach.example.edu/login#sso_token=")
    token = response.headers["location"].split("#sso_token=")[1]
    me = response.client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["role"] == "developer"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"state": "forged"}, "state"),
        ({"aud": "someone-else.apps.googleusercontent.com"}, "token"),
        ({"iss": "https://evil.example"}, "token"),
        ({"nonce": "replayed"}, "token"),
        ({"exp": 1}, "token"),
        ({"email_verified": False}, "unverified"),
    ],
)
def test_failures_redirect_with_a_short_code(
    flow: Flow, changes: dict[str, Any], code: str
) -> None:
    response = flow(**changes)
    assert response.status_code == 302
    assert response.headers["location"] == f"{BASE}/login?sso_error={code}"


def test_disallowed_domain_is_refused_and_allowed_one_passes(flow: Flow) -> None:
    refused = flow(_sso(allowed_domains=("thapar.edu",)))
    assert refused.headers["location"] == f"{BASE}/login?sso_error=not_allowed"
    allowed = flow(_sso(allowed_domains=("example.edu",)))
    assert "#sso_token=" in allowed.headers["location"]


def test_callback_without_the_state_cookie_is_refused(tmp_path: Any) -> None:
    with TestClient(create_app(_config(tmp_path, _sso())), follow_redirects=False) as client:
        response = client.get(f"{API}/auth/google/callback?code=x&state=y")
    assert response.headers["location"] == f"{BASE}/login?sso_error=state"


def test_existing_user_keeps_their_role(flow: Flow, tmp_path: Any) -> None:
    first = flow()
    client = first.client
    admin = client.post(
        f"{API}/auth/login", json={"username": "admin", "password": "kavach-admin"}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {admin}"}
    users = client.get(f"{API}/users", headers=headers).json()
    user_id = next(user["id"] for user in users if user["username"] == "asha@example.edu")
    assert (
        client.patch(f"{API}/users/{user_id}", json={"role": "auditor"}, headers=headers)
    ).status_code == 200
    second = flow()
    token = second.headers["location"].split("#sso_token=")[1]
    me = second.client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["role"] == "auditor"
