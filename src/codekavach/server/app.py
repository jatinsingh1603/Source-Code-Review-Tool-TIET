"""The FastAPI application: the API under ``/api/v1``, its docs at ``/api/docs``, the UI at ``/``.

Owning epic: E32.

``create_app(config)`` builds the server state (database, workers, event hub), seeds the first
admin and the sample project, and mounts the routers. The built dashboard (``ui/dist``) is served
from ``/`` with a single-page-application fallback; without a build a short page explains how to
make one. CORS is off unless origins are configured, or ``CODEKAVACH_DEV=1`` allows the Vite dev
server.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Final

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from codekavach.core.log import get_logger
from codekavach.server.config import ServerConfig
from codekavach.server.errors import install_handlers
from codekavach.server.middleware import install_middleware
from codekavach.server.state import ServerState

_log = get_logger("codekavach.server.app")

API_PREFIX: Final = "/api/v1"
NO_UI_PAGE: Final = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CodeKavach server</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:44rem;margin:4rem auto;padding:0 1rem;
color:#1b2430;line-height:1.5}code{background:#eef1f5;padding:.1rem .3rem;border-radius:4px}
h1{font-size:1.6rem}</style></head><body>
<h1>CodeKavach API server is running</h1>
<p>The web dashboard has not been built, so only the REST API is available.</p>
<p>Build it with <code>cd ui &amp;&amp; npm ci &amp;&amp; npm run build</code> and restart
<code>codekavach serve</code>, or pass <code>--ui-dir</code>.</p>
<p>API documentation: <a href="/api/docs">/api/docs</a> &middot; health:
<a href="/api/v1/health">/api/v1/health</a></p>
</body></html>"""


def _api_router() -> APIRouter:
    from codekavach.server.routers import (  # noqa: PLC0415
        auth,
        findings,
        platform,
        projects,
        scans,
        system,
    )

    router = APIRouter(prefix=API_PREFIX)
    for module in (system, platform, auth, projects, scans, findings):
        router.include_router(module.router)
    return router


def _mount_ui(app: FastAPI, ui_dir: Path | None) -> None:
    root = ui_dir.resolve() if ui_dir is not None and (ui_dir / "index.html").is_file() else None

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str, request: Request) -> Response:
        if path.startswith("api/"):
            return JSONResponse(
                {"ok": False, "error": {"code": "not_found", "message": "no such endpoint"},
                 "detail": "no such endpoint"},
                status_code=404,
            )  # fmt: skip
        if root is None:
            return HTMLResponse(NO_UI_PAGE)
        candidate = (root / path).resolve() if path else root / "index.html"
        if candidate.is_file() and (candidate == root or root in candidate.parents):
            response = FileResponse(candidate)
            if "/assets/" in f"/{path}":
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return response
        return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})


def create_app(config: ServerConfig | None = None, *, state: ServerState | None = None) -> FastAPI:
    """The application for ``config`` (or an existing ``state``, for tests)."""
    server = state or ServerState(config or ServerConfig())
    seeded = server.bootstrap()
    _log.info("server_ready", **{key: str(value) for key, value in seeded.items()})

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            server.close()

    app = FastAPI(
        title="CodeKavach API",
        version="1.0",
        description="Privacy-preserving, LLM-assisted secure source code review.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.server = server
    install_handlers(app)
    install_middleware(app, max_body_bytes=server.config.max_upload_bytes + 1024 * 1024)
    origins = list(server.config.effective_cors_origins())
    if origins:
        if "*" in origins:
            raise ValueError("CORS with credentials cannot allow every origin ('*')")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["Authorization", "Content-Type", "Last-Event-ID", "X-Request-ID"],
        )
    app.include_router(_api_router())
    _mount_ui(app, server.config.ui_dir)
    return app
