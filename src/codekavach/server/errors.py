"""API errors and the JSON error body.

Owning epic: E32.

Every error leaves the server as ``{"ok": false, "error": {"code", "message", "hint"},
"detail": message, "request_id"}``: a stable machine code, a human message and never a stack
trace. ``detail`` repeats the message for clients written against FastAPI's default shape.
"""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from codekavach.core.log import get_logger

_log = get_logger("codekavach.server.errors")


class ApiError(Exception):
    """An error with a machine code, a message, an optional hint and an HTTP status."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        hint: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.headers = headers
        self.status = status
        self.code = code
        self.message = message
        self.hint = hint


def not_found(what: str) -> ApiError:
    """A 404 for ``what``."""
    return ApiError(404, "not_found", f"{what} not found")


def _body(request: Request, code: str, message: str, hint: str | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {"code": code, "message": message, "hint": hint},
        "detail": message,
        "request_id": getattr(request.state, "request_id", None),
    }


def install_handlers(app: FastAPI) -> None:
    """Register the handlers that turn every error into the JSON body above."""

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, error: ApiError) -> JSONResponse:
        headers = dict(error.headers or {})
        if error.status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            _body(request, error.code, error.message, error.hint),
            status_code=error.status,
            headers=headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(error.status_code, "http_error")
        return JSONResponse(
            _body(request, code, str(error.detail)),
            status_code=error.status_code,
            headers=getattr(error, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, error: RequestValidationError) -> JSONResponse:
        problems = [
            f"{'.'.join(str(part) for part in item.get('loc', ()))}: {item.get('msg', '')}"
            for item in error.errors()
        ]
        return JSONResponse(
            _body(request, "validation_error", "; ".join(problems) or "invalid request"),
            status_code=422,
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, error: Exception) -> JSONResponse:
        from codekavach.privacy.egress.ledger import LedgerKeyError  # noqa: PLC0415
        from codekavach.privacy.vault.errors import VaultKeyError  # noqa: PLC0415

        if isinstance(error, LedgerKeyError | VaultKeyError):
            _log.warning("api_key_mismatch", error_type=type(error).__name__, path=request.url.path)
            return JSONResponse(
                _body(
                    request,
                    "vault_key_mismatch",
                    "This scan's stored payloads are encrypted with another vault key, "
                    "so they cannot be shown.",
                    "The vault passphrase changed since the scan ran. Restore the old "
                    "CODEKAVACH_VAULT_PASSPHRASE, or run the scan again.",
                ),
                status_code=409,
            )
        _log.error("api_unhandled_error", error_type=type(error).__name__, path=request.url.path)
        return JSONResponse(
            _body(request, "internal_error", "internal server error"), status_code=500
        )
