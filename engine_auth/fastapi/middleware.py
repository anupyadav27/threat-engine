"""
FastAPI AuthMiddleware — for the API gateway.

Validates access_token cookie, builds AuthContext, and forwards it
as X-Auth-Context header to downstream engines.

Engines trust X-Auth-Context because they are on an internal network
(EKS pod-to-pod communication).
"""

from __future__ import annotations

import json
import logging
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from engine_auth.core.models import AuthContext

logger = logging.getLogger(__name__)

# Paths that don't require authentication
PUBLIC_PATHS = {
    "/",
    "/health",
    "/healthz",
    "/ready",
    "/docs",
    "/openapi.json",
    "/api/auth/login",
    "/api/auth/login/",
    "/api/auth/register",
    "/api/auth/register/",
    "/api/auth/invite/accept",
    "/api/auth/invite/accept/",
    "/api/auth/google/login",
    "/api/auth/google/login/",
    "/api/auth/google/callback",
    "/api/auth/google/callback/",
    "/api/auth/csrf",
    "/api/auth/csrf/",
}

# Path prefixes that don't require authentication (checked with startswith)
PUBLIC_PREFIXES = (
    "/gateway/",       # Gateway management endpoints (health, services, etc.)
)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Validate access_token cookie and set X-Auth-Context header for downstream services.

    This middleware connects to the auth database to validate tokens.
    """

    def __init__(self, app, db_config: dict | None = None):
        super().__init__(app)
        self.db_config = db_config or self._default_db_config()
        self._pool = None

    async def dispatch(self, request: Request, call_next):
        # Skip auth for public paths
        path = request.url.path.rstrip("/")
        if path in {p.rstrip("/") for p in PUBLIC_PATHS}:
            return await call_next(request)

        # Skip auth for public prefixes (gateway management, etc.)
        if request.url.path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)

        # Skip OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Get token from cookie
        raw_token = request.cookies.get("access_token")
        if not raw_token:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
            )

        # Validate token and get auth context
        try:
            auth_ctx = await self._validate_token(raw_token)
        except Exception as e:
            logger.error("Token validation failed: %s", e)
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired session"},
            )

        if not auth_ctx:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired session"},
            )

        # Set auth context on request state (for FastAPI dependencies)
        request.state.auth_context = auth_ctx

        # Forward auth context as header to downstream engines
        # We modify the request scope to add the header
        auth_header = auth_ctx.to_header_json()

        # Store for forwarding
        request.state.auth_header = auth_header

        response = await call_next(request)
        return response

    async def _validate_token(self, raw_token: str) -> AuthContext | None:
        """Validate token against auth database using token_hint."""
        import asyncpg
        from django.contrib.auth.hashers import check_password

        pool = await self._get_pool()

        hint = raw_token[:8]

        # Query sessions with matching token_hint
        rows = await pool.fetch(
            """
            SELECT
                s.id, s.token, s.user_id, s.permissions_cache, s.scope_cache,
                u.email,
                r.name as role_name, r.level as role_level, r.scope_level as role_scope_level
            FROM user_sessions s
            JOIN users u ON u.id = s.user_id
            LEFT JOIN user_roles ur ON ur.user_id = s.user_id
            LEFT JOIN roles r ON r.id = ur.role_id
            WHERE s.token_hint = $1
              AND s.revoked = false
              AND s.expires_at > NOW()
            ORDER BY r.level ASC
            LIMIT 10
            """,
            hint,
        )

        for row in rows:
            if check_password(raw_token, row["token"]):
                return AuthContext.from_session_cache(
                    user_id=row["user_id"],
                    email=row["email"],
                    role_name=row["role_name"] or "none",
                    role_level=row["role_level"] or 99,
                    role_scope_level=row["role_scope_level"] or "account",
                    permissions_cache=row["permissions_cache"] or [],
                    scope_cache=row["scope_cache"] or {},
                )

        # Fallback: try sessions without token_hint (old sessions)
        rows = await pool.fetch(
            """
            SELECT
                s.id, s.token, s.user_id, s.permissions_cache, s.scope_cache,
                u.email,
                r.name as role_name, r.level as role_level, r.scope_level as role_scope_level
            FROM user_sessions s
            JOIN users u ON u.id = s.user_id
            LEFT JOIN user_roles ur ON ur.user_id = s.user_id
            LEFT JOIN roles r ON r.id = ur.role_id
            WHERE s.token_hint IS NULL
              AND s.revoked = false
              AND s.expires_at > NOW()
            ORDER BY r.level ASC
            LIMIT 100
            """,
        )

        for row in rows:
            if check_password(raw_token, row["token"]):
                # Backfill token_hint
                await pool.execute(
                    "UPDATE user_sessions SET token_hint = $1 WHERE id = $2",
                    hint,
                    row["id"],
                )
                return AuthContext.from_session_cache(
                    user_id=row["user_id"],
                    email=row["email"],
                    role_name=row["role_name"] or "none",
                    role_level=row["role_level"] or 99,
                    role_scope_level=row["role_scope_level"] or "account",
                    permissions_cache=row["permissions_cache"] or [],
                    scope_cache=row["scope_cache"] or {},
                )

        return None

    async def _get_pool(self):
        """Get or create asyncpg connection pool."""
        if self._pool is None:
            import asyncpg

            self._pool = await asyncpg.create_pool(
                host=self.db_config["host"],
                port=self.db_config["port"],
                database=self.db_config["database"],
                user=self.db_config["user"],
                password=self.db_config["password"],
                min_size=2,
                max_size=10,
            )
        return self._pool

    def _default_db_config(self) -> dict:
        """Default DB config from environment."""
        return {
            "host": os.getenv("AUTH_DB_HOST", os.getenv("USERPORTAL_DB_HOST", "localhost")),
            "port": int(os.getenv("AUTH_DB_PORT", os.getenv("USERPORTAL_DB_PORT", "5432"))),
            "database": os.getenv("AUTH_DB_NAME", os.getenv("USERPORTAL_DB_NAME", "threat_engine_userportal")),
            "user": os.getenv("AUTH_DB_USER", os.getenv("USERPORTAL_DB_USER", "postgres")),
            "password": os.getenv("AUTH_DB_PASSWORD", os.getenv("USERPORTAL_DB_PASSWORD", "")),
        }
