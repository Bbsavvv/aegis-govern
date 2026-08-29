from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from aegis_core.config import get_settings

API_PREFIX = "/api"
API_KEY_HEADER = "X-API-Key"


def _configured_api_key() -> str:
    return (get_settings().api_key or "").strip()


def _header_api_key(request: Request) -> str:
    return (request.headers.get(API_KEY_HEADER) or "").strip()


def api_keys_match(provided: str, expected: str) -> bool:
    if not provided or not expected:
        return False
    provided_bytes = provided.encode("utf-8")
    expected_bytes = expected.encode("utf-8")
    if len(provided_bytes) != len(expected_bytes):
        hmac.compare_digest(expected_bytes, expected_bytes)
        return False
    return hmac.compare_digest(provided_bytes, expected_bytes)


def is_protected_api_path(path: str) -> bool:
    return path == API_PREFIX or path.startswith(API_PREFIX + "/")


class ApiKeyMiddleware(BaseHTTPMiddleware):
    """Require X-API-Key on every request whose path is under /api/."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "OPTIONS" or not is_protected_api_path(request.url.path):
            return await call_next(request)

        expected = _configured_api_key()
        if not expected:
            return JSONResponse(
                status_code=503,
                content={"detail": "API key is not configured (set AEGIS_API_KEY)"},
            )

        provided = _header_api_key(request)
        if not api_keys_match(provided, expected):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing X-API-Key"},
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return await call_next(request)
