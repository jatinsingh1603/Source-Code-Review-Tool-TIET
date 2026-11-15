"""HTTP middleware: request identifiers, security headers, body-size limit.

Owning epic: E32.

API responses get ``Content-Security-Policy: default-src 'none'; frame-ancestors 'none'``,
``X-Content-Type-Options: nosniff``, ``Referrer-Policy: no-referrer``, ``X-Frame-Options: DENY``
and, when authenticated, ``Cache-Control: no-store``. The dashboard's static pages get a CSP that
allows their own scripts and styles only. Request bodies above the limit are refused with 413
before they are read; a body sent without ``Content-Length`` (chunked) is counted as it arrives
and refused once it passes the same limit. The ``access_token`` query parameter is redacted from
the access log.
"""

import logging
import re
import secrets
from collections.abc import Awaitable, Callable
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

API_CSP: Final = "default-src 'none'; frame-ancestors 'none'"
UI_CSP: Final = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' "
    "https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; "
    "img-src 'self' data: blob:; connect-src 'self'; frame-src 'self' blob:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)
DOCS_PATHS: Final = ("/api/docs", "/api/redoc", "/api/openapi.json")


_TOKEN_PARAM: Final = re.compile(r"(?i)(access_token=)[^&\s\"]*")
# The Google sign-in callback carries the one-time authorisation code and the state.
_SSO_CALLBACK: Final = re.compile(r"(?i)(/auth/google/callback\?)[^\s\"]*")
ACCESS_LOGGER: Final = "uvicorn.access"


def redact_token(text: str) -> str:
    """``text`` without ``access_token`` values and without a sign-in callback's query."""
    return _SSO_CALLBACK.sub(r"\1[redacted]", _TOKEN_PARAM.sub(r"\1[redacted]", text))


class TokenRedactor(logging.Filter):
    """Keeps ``?access_token=`` bearer tokens and sign-in callback queries out of the access log."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact the record in place; never drops it."""
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact_token(arg) if isinstance(arg, str) else arg for arg in record.args
            )
        if isinstance(record.msg, str):
            record.msg = redact_token(record.msg)
        return True


def install_log_redaction() -> None:
    """Add the token redactor to the access logger (once)."""
    logger = logging.getLogger(ACCESS_LOGGER)  # noqa: TID251 - uvicorn's stdlib logger
    if not any(isinstance(item, TokenRedactor) for item in logger.filters):
        logger.addFilter(TokenRedactor())


class BodyLimit:
    """Counts the request body as it is read; past ``max_bytes`` the read fails with 413.

    The ``Content-Length`` check below cannot see a chunked body, which carries no length.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Hand the application a ``receive`` that enforces the limit."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        seen = 0

        async def counted() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise HTTPException(status_code=413, detail="request body too large")
            return message

        await self.app(scope, counted, send)


def install_middleware(app: FastAPI, *, max_body_bytes: int) -> None:
    """Add the middleware to ``app``."""
    app.add_middleware(BodyLimit, max_bytes=max_body_bytes)

    @app.middleware("http")
    async def security(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("x-request-id", "")[:64] or secrets.token_hex(8)
        request.state.request_id = request_id
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > max_body_bytes:
            return JSONResponse(
                {
                    "ok": False,
                    "error": {"code": "body_too_large", "message": "request body too large"},
                    "detail": "request body too large",
                    "request_id": request_id,
                },
                status_code=413,
            )
        response = await call_next(request)
        path = request.url.path
        headers = response.headers
        headers["X-Request-ID"] = request_id
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if path.startswith("/api/") and not path.startswith(DOCS_PATHS):
            headers.setdefault("Content-Security-Policy", API_CSP)
            if "authorization" in request.headers or "access_token" in request.query_params:
                headers["Cache-Control"] = "no-store"
            else:
                headers.setdefault("Cache-Control", "no-store")
        elif not path.startswith(DOCS_PATHS):
            headers.setdefault("Content-Security-Policy", UI_CSP)
        if request.url.scheme == "https":
            headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response
