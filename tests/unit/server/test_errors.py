"""The JSON error body for failures the dashboard can explain."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from codekavach.privacy.egress.ledger import LedgerKeyError
from codekavach.server.errors import install_handlers


def _client(error: Exception) -> TestClient:
    app = FastAPI()
    install_handlers(app)

    @app.get("/boom")
    def boom() -> None:
        raise error

    return TestClient(app, raise_server_exceptions=False)


def test_a_vault_key_mismatch_is_a_409_with_a_hint() -> None:
    response = _client(LedgerKeyError("the key does not open this ledger")).get("/boom")
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "vault_key_mismatch"
    assert "passphrase" in error["hint"]


def test_other_errors_stay_internal() -> None:
    response = _client(RuntimeError("secret detail")).get("/boom")
    assert response.status_code == 500
    assert "secret detail" not in response.text
