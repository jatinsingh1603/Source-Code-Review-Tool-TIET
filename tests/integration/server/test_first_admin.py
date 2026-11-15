"""The first admin account: no built-in password, a forced change, and the recovery command."""

import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from codekavach.server.app import create_app
from codekavach.server.config import (
    ADMIN_PASSWORD_ENV,
    ADMIN_PASSWORD_FILE_ENV,
    FORCE_PASSWORD_CHANGE_ENV,
    INITIAL_PASSWORD_FILE,
    AdminPasswordError,
    ServerConfig,
)
from codekavach.server.db.engine import Database, add_missing_columns
from tests.support.cli import run_cli
from tests.support.server import ADMIN_PASSWORD

API = "/api/v1"
NEW_PASSWORD = "chosen-by-the-admin-42"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _no_ambient_password(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (ADMIN_PASSWORD_ENV, ADMIN_PASSWORD_FILE_ENV, FORCE_PASSWORD_CHANGE_ENV):
        monkeypatch.delenv(name, raising=False)


def _client(config: ServerConfig) -> Iterator[tuple[TestClient, Any]]:
    app = create_app(config)
    with TestClient(app) as client:
        yield client, app.state.server


@pytest.fixture
def generated(tmp_path: Path) -> Iterator[tuple[TestClient, Any]]:
    yield from _client(ServerConfig(data_dir=tmp_path, ui_dir=None, workers=1))


def _login(client: TestClient, password: str, username: str = "admin") -> Any:
    return client.post(f"{API}/auth/login", json={"username": username, "password": password})


def _bearer(response: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_no_password_is_built_in(generated: tuple[TestClient, Any]) -> None:
    client, _state = generated
    for guess in ("kavach-admin", "admin", "password", "changeme"):
        assert _login(client, guess).status_code == 401


def test_generated_password_is_handed_out_once_and_kept_in_a_private_file(
    generated: tuple[TestClient, Any],
) -> None:
    client, state = generated
    path = state.config.initial_password_path
    assert path.name == INITIAL_PASSWORD_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 or sys.platform == "win32"
    password = state.take_generated_admin_password()
    assert password is not None and len(password) >= 20
    assert state.take_generated_admin_password() is None
    assert path.read_text(encoding="utf-8").strip() == password
    # Only the hash is stored: the value is nowhere in the database file.
    state.db.dispose()
    assert password.encode() not in state.config.db_path.read_bytes()
    assert _login(client, password).status_code == 200
    assert not path.exists(), "the file goes at the first admin sign-in"


def test_first_sign_in_must_choose_a_new_password(generated: tuple[TestClient, Any]) -> None:
    client, state = generated
    password = state.take_generated_admin_password()
    response = _login(client, password)
    assert response.json()["must_change_password"] is True
    assert response.json()["user"]["must_change_password"] is True
    headers = _bearer(response)
    blocked = client.get(f"{API}/projects", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"
    assert client.post(f"{API}/users", json={}, headers=headers).status_code == 403
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 200
    same = {"current_password": password, "new_password": password}
    assert client.post(f"{API}/auth/change-password", json=same, headers=headers).status_code == 400
    short = {"current_password": password, "new_password": "short"}
    assert (
        client.post(f"{API}/auth/change-password", json=short, headers=headers).status_code == 422
    )
    good = {"current_password": password, "new_password": NEW_PASSWORD}
    changed = client.post(f"{API}/auth/change-password", json=good, headers=headers)
    assert changed.status_code == 200, changed.text
    assert changed.json()["user"]["must_change_password"] is False
    assert client.get(f"{API}/projects", headers=headers).status_code == 200
    assert _login(client, password).status_code == 401
    again = _login(client, NEW_PASSWORD)
    assert again.status_code == 200
    assert again.json()["must_change_password"] is False


def test_a_supplied_password_is_temporary_too_and_leaves_no_file(tmp_path: Path) -> None:
    config = ServerConfig(data_dir=tmp_path, ui_dir=None, workers=1, admin_password=ADMIN_PASSWORD)
    for client, state in _client(config):
        assert state.take_generated_admin_password() is None
        assert not config.initial_password_path.exists()
        response = _login(client, ADMIN_PASSWORD)
        assert response.json()["must_change_password"] is True
        assert client.get(f"{API}/scans", headers=_bearer(response)).status_code == 403


def test_password_file_and_opt_out_come_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = tmp_path / "admin-secret"
    secret.write_text(ADMIN_PASSWORD + "\n", encoding="utf-8")
    monkeypatch.setenv(ADMIN_PASSWORD_FILE_ENV, str(secret))
    monkeypatch.setenv(FORCE_PASSWORD_CHANGE_ENV, "0")
    config = ServerConfig(data_dir=tmp_path / "data", ui_dir=None, workers=1)
    assert config.admin_password == ADMIN_PASSWORD
    assert config.force_password_change is False
    for client, _state in _client(config):
        response = _login(client, ADMIN_PASSWORD)
        assert response.status_code == 200
        assert client.get(f"{API}/projects", headers=_bearer(response)).status_code == 200


def test_unusable_supplied_passwords_stop_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ADMIN_PASSWORD_FILE_ENV, str(tmp_path / "missing"))
    with pytest.raises(AdminPasswordError, match="cannot be read"):
        ServerConfig(data_dir=tmp_path / "a", ui_dir=None)
    monkeypatch.delenv(ADMIN_PASSWORD_FILE_ENV)
    config = ServerConfig(
        data_dir=tmp_path / "b",
        ui_dir=None,
        workers=1,
        admin_password="short",  # pragma: allowlist secret
    )
    with pytest.raises(AdminPasswordError, match="at least 10"):
        create_app(config)


def test_a_password_an_admin_sets_for_someone_is_temporary(tmp_path: Path) -> None:
    config = ServerConfig(data_dir=tmp_path, ui_dir=None, workers=1, admin_password=ADMIN_PASSWORD)
    for client, _state in _client(config):
        first = _bearer(_login(client, ADMIN_PASSWORD))
        body = {"current_password": ADMIN_PASSWORD, "new_password": NEW_PASSWORD}
        assert client.post(f"{API}/auth/change-password", json=body, headers=first).is_success
        # pragma: allowlist nextline secret
        user = {"username": "meera", "password": "set-by-the-admin", "role": "developer"}
        created = client.post(f"{API}/users", json=user, headers=first)
        assert created.status_code == 201, created.text
        assert created.json()["must_change_password"] is True
        meera = _login(client, "set-by-the-admin", "meera")
        assert meera.json()["must_change_password"] is True
        assert client.get(f"{API}/findings", headers=_bearer(meera)).status_code == 403
        # pragma: allowlist nextline secret
        change = {"current_password": "set-by-the-admin", "new_password": "meera-own-password"}
        assert client.post(
            f"{API}/auth/change-password", json=change, headers=_bearer(meera)
        ).is_success
        assert client.get(f"{API}/projects", headers=_bearer(meera)).status_code == 200
        # An admin reset makes it temporary again; a service account can be exempted.
        reset = client.patch(
            f"{API}/users/{created.json()['id']}",
            json={"password": "reset-by-the-admin"},  # pragma: allowlist secret
            headers=first,
        )
        assert reset.json()["must_change_password"] is True
        exempt = client.patch(
            f"{API}/users/{created.json()['id']}",
            json={"must_change_password": False},
            headers=first,
        )
        assert exempt.json()["must_change_password"] is False


def test_reset_password_command_recovers_the_admin(tmp_path: Path) -> None:
    config = ServerConfig(data_dir=tmp_path, ui_dir=None, workers=1, admin_password=ADMIN_PASSWORD)
    for client, _state in _client(config):
        old = _bearer(_login(client, ADMIN_PASSWORD))
        result = run_cli(["admin", "reset-password", "--data-dir", str(tmp_path)])
        assert result.exit_code == 0, result.stderr
        temporary = result.stdout.strip()
        assert len(temporary) >= 20 and "\n" not in temporary
        assert temporary not in result.stderr
        assert client.get(f"{API}/auth/me", headers=old).status_code == 401, "sessions revoked"
        assert _login(client, ADMIN_PASSWORD).status_code == 401
        response = _login(client, temporary)
        assert response.status_code == 200
        assert response.json()["must_change_password"] is True
        chosen = run_cli(
            ["admin", "reset-password", "--data-dir", str(tmp_path), "--password-stdin"],
            input=NEW_PASSWORD + "\n",
        )
        assert chosen.exit_code == 0, chosen.stderr
        assert NEW_PASSWORD not in chosen.stdout + chosen.stderr
        assert _login(client, NEW_PASSWORD).status_code == 200
    from sqlalchemy import select  # noqa: PLC0415

    from codekavach.server.db.models import AuditEvent  # noqa: PLC0415

    db = Database(config.db_path)
    try:
        with db.transaction() as session:
            actions = [
                row.action
                for row in session.scalars(select(AuditEvent))
                if row.actor == "cli:admin"
            ]
    finally:
        db.dispose()
    assert actions == ["user.password_reset", "user.password_reset"]


def test_reset_password_command_refuses_what_it_cannot_do(tmp_path: Path) -> None:
    missing = run_cli(["admin", "reset-password", "--data-dir", str(tmp_path / "none")])
    assert missing.exit_code != 0
    assert "no server database" in missing.stderr
    config = ServerConfig(data_dir=tmp_path, ui_dir=None, workers=1, admin_password=ADMIN_PASSWORD)
    for _ in _client(config):
        unknown = run_cli(
            ["admin", "reset-password", "--data-dir", str(tmp_path), "--username", "ghost"]
        )
        assert unknown.exit_code != 0
        assert "no account named ghost" in unknown.stderr
        short = run_cli(
            ["admin", "reset-password", "--data-dir", str(tmp_path), "--password-stdin"],
            input="short\n",
        )
        assert short.exit_code != 0
        assert "at least 10" in short.stderr


def test_an_older_database_gains_the_new_column(tmp_path: Path) -> None:
    """A database made before ``must_change_password`` existed is upgraded in place."""
    from sqlalchemy import text  # noqa: PLC0415

    db = Database(tmp_path / "server.db")
    with db.engine.begin() as connection:
        connection.execute(text("ALTER TABLE users DROP COLUMN must_change_password"))
        connection.execute(
            text(
                "INSERT INTO users (id, username, full_name, email, role, password_hash, active,"
                " created_at) VALUES ('usr_old', 'old', '', '', 'viewer', 'x', 1,"
                " '2026-01-01 00:00:00')"
            )
        )
    assert add_missing_columns(db.engine) == ["users.must_change_password"]
    assert add_missing_columns(db.engine) == []
    with db.engine.begin() as connection:
        assert connection.execute(text("SELECT must_change_password FROM users")).scalar() == 0
    db.dispose()
