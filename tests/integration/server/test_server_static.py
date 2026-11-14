"""The dashboard build served at ``/``: SPA fallback for pages, a real 404 for missing assets."""

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from codekavach.server.app import create_app
from codekavach.server.config import ServerConfig


def test_a_missing_asset_is_a_404_not_the_index_page(tmp_path: Path) -> None:
    ui = tmp_path / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text("<!doctype html><title>CodeKavach</title>", encoding="utf-8")
    (ui / "assets" / "Page-new.js").write_text("export default 1;", encoding="utf-8")
    config = ServerConfig(data_dir=tmp_path / "data", ui_dir=ui, workers=1)
    with TestClient(create_app(config)) as client:
        assert client.get("/assets/Page-new.js").status_code == 200
        stale = client.get("/assets/Page-old.js")
        assert stale.status_code == 404
        assert not stale.headers["content-type"].startswith("text/html")
        page = client.get("/privacy/policy")
        assert page.status_code == 200
        assert page.headers["content-type"].startswith("text/html")
