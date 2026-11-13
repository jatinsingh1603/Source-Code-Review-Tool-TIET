"""HTTP middleware: request identifiers, security headers, body-size limit.

Owning epic: E32.

API responses get ``Content-Security-Policy: default-src 'none'; frame-ancestors 'none'``,
``X-Content-Type-Options: nosniff``, ``Referrer-Policy: no-referrer``, ``X-Frame-Options: DENY``
and, when authenticated, ``Cache-Control: no-store``. The dashboard's static pages get a CSP that
allows their own scripts and styles only. Request bodies above the limit are refused with 413
before they are read. The ``access_token`` query parameter is redacted from the access log.
"""

import logging
import re
import secrets
from collections.abc import Awaitable, Callable
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

API_CSP: Final = "default-src 'none'; frame-ancestors 'none'"
UI_CSP: Final = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' "
    "https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; "
    "img-src 'self' data: blob:; connect-src 'self'; frame-src 'self' blob:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)
DOCS_PATHS: Final = ("/api/docs", "/api/redoc", "/api/openapi.json")


_TOKEN_PARAM: Final = re.compile(r"(?i)(access_token=)[^&\s\"]*")
ACCESS_LOGGER: Final = "uvicorn.access"


def redact_token(text: str) -> str:
    """``text`` with the value of any ``access_token`` query parameter replaced."""
    return _TOKEN_PARAM.sub(r"\1[redacted]", text)


class TokenRedactor(logging.Filter):
    """Keeps bearer tokens passed as ``?access_token=`` out of the access log."""

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


def install_middleware(app: FastAPI, *, max_body_bytes: int) -> None:
    """Add the middleware to ``app``."""

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
