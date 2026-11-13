"""``codekavach serve`` must not print an operator-chosen admin password (it lands in logs)."""

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

import uvicorn

from codekavach.cli.serve import serve_command
from codekavach.server.config import ADMIN_PASSWORD_ENV, DEFAULT_ADMIN_PASSWORD


def _banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> str:
    def fake_run(app: Any, *_args: Any, **_kwargs: Any) -> None:
        # Uvicorn would close the server state when the app's lifespan ends; without this the
        # database connections stay open until garbage collection, which Python 3.13 reports.
        app.state.server.close()

    monkeypatch.setattr(uvicorn, "run", fake_run)
    serve_command(data_dir=tmp_path / "data", ui_dir=None, workers=1)
    captured = capsys.readouterr()
    return captured.out + captured.err


def test_chosen_password_is_not_printed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    chosen = "s3cret-Operator-Choice-71"
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, chosen)
    out = _banner(tmp_path, monkeypatch, capsys)
    assert chosen not in out
    assert ADMIN_PASSWORD_ENV in out


def test_default_password_is_printed_as_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(ADMIN_PASSWORD_ENV, raising=False)
    out = _banner(tmp_path, monkeypatch, capsys)
    assert f"admin / {DEFAULT_ADMIN_PASSWORD}" in out
    assert "change it" in out
