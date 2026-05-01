"""
API Key Authentication Middleware.

Protects all non-health endpoints with a static API key checked via
the `X-API-Key` request header.

Configuration:
  VUL_FIX_API_KEY  — required env var; if not set the engine refuses to start.

Exempt paths (no auth required):
  /api/v1/health/*
  /health
  /
  /docs
  /openapi.json
  /redoc

Usage: mounted in api_server.py via app.add_middleware(APIKeyMiddleware)
"""

import logging
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths that do not require authentication
_EXEMPT_PREFIXES = (
    "/api/v1/health",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
)
_EXEMPT_EXACT = {"/"}


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that enforces X-API-Key header authentication.

    - Returns 401 if header is missing.
    - Returns 403 if key is wrong.
    - Logs all auth failures with client IP (never logs the submitted key).
    """

    def __init__(self, app, api_key: str):
        super().__init__(app)
        if not api_key:
            raise RuntimeError(
                "VUL_FIX_API_KEY is not set. "
                "Set this environment variable before starting the engine."
            )
        self._api_key = api_key

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip auth for exempt paths
        if path in _EXEMPT_EXACT or any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        submitted = request.headers.get("X-API-Key", "")
        client_ip = request.client.host if request.client else "unknown"

        if not submitted:
            logger.warning(
                f"[Auth] 401 missing X-API-Key  path={path}  ip={client_ip}"
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorised",
                    "detail": "X-API-Key header is required.",
                },
            )

        if submitted != self._api_key:
            logger.warning(
                f"[Auth] 403 invalid X-API-Key  path={path}  ip={client_ip}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "detail": "Invalid API key.",
                },
            )

        return await call_next(request)
