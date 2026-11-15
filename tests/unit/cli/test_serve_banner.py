"""What ``codekavach serve`` prints about the admin account at start-up.

A password the operator chose must never be printed (the banner lands in container logs); a
generated one is printed exactly once, at the start that created the account.
"""

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

import uvicorn

from codekavach.cli.errors import UsageError
from codekavach.cli.serve import serve_command
from codekavach.server.config import (
    ADMIN_PASSWORD_ENV,
    ADMIN_PASSWORD_FILE_ENV,
    INITIAL_PASSWORD_FILE,
)


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
    chosen = "s3cret-Operator-Choice-71"  # pragma: allowlist secret
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, chosen)
    out = _banner(tmp_path, monkeypatch, capsys)
    assert chosen not in out
    assert ADMIN_PASSWORD_ENV in out
    assert not (tmp_path / "data" / INITIAL_PASSWORD_FILE).exists()


def test_generated_password_is_printed_once_with_instructions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(ADMIN_PASSWORD_ENV, raising=False)
    monkeypatch.delenv(ADMIN_PASSWORD_FILE_ENV, raising=False)
    first = _banner(tmp_path, monkeypatch, capsys)
    kept = tmp_path / "data" / INITIAL_PASSWORD_FILE
    password = kept.read_text(encoding="utf-8").strip()
    assert len(password) >= 20
    assert first.count(password) == 1
    assert "user name: admin" in first
    assert "choose a new password" in first
    assert str(kept) in first
    # A second start does not print it again; it points at the file while it is unused.
    second = _banner(tmp_path, monkeypatch, capsys)
    assert password not in second
    assert str(kept) in second
    kept.unlink()
    third = _banner(tmp_path, monkeypatch, capsys)
    assert "codekavach admin reset-password" in third


def test_an_unusable_password_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ADMIN_PASSWORD_ENV, "short")
    with pytest.raises(UsageError, match="at least 10"):
        _banner(tmp_path, monkeypatch, capsys)
