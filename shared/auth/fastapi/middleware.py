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
    "/api/v1/agents/bootstrap",
    "/api/v1/agents/bootstrap/",
}

# Path prefixes that don't require authentication (checked with startswith)
PUBLIC_PREFIXES = (
    "/gateway/",         # Gateway management endpoints (health, services, etc.)
    "/api/v1/health",    # Health check endpoints
    "/argo/",            # Argo Workflows UI (internal tool, no user auth needed)
    "/api/v1/billing/webhooks/stripe",  # Stripe calls this directly — auth via Stripe-Signature HMAC
    "/vulnerability/",  # Vulnerability engine uses API key auth — Next.js server-side proxy has no session cookie
    "/api/v1/agent/download/",  # Agent script download — no secrets in script; token passed at install time
    "/api/v1/internal/",  # Internal cluster-only endpoints (e.g. CDR cron trigger, onboarding agent validate)
                          # Never exposed via ingress or gateway — only reachable from within the cluster.
    # NOTE: /api/v1/views/ is NOT here — BFF views must be authenticated so
    # that AuthMiddleware builds X-Auth-Context and forwards it to downstream
    # engines.  Without this the engines never receive a tenant/user context.
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

        # If X-Auth-Context is already present (internal service-to-service call from
        # the API gateway), trust it directly without requiring a session cookie.
        existing_ctx_header = request.headers.get("x-auth-context") or request.headers.get("X-Auth-Context")
        if existing_ctx_header:
            import json as _json_mid
            try:
                from engine_auth.core.models import AuthContext as _AC
                ctx_data = _json_mid.loads(existing_ctx_header)
                request.state.auth_context = _AC.from_dict(ctx_data)
                request.state.auth_header = existing_ctx_header
            except Exception as _ctx_err:
                logger.error("Invalid X-Auth-Context header: %s", _ctx_err)
                return JSONResponse(status_code=401, content={"detail": "Invalid auth context"})
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

        # If the client sent X-Active-Tenant-Id (scope bar selection), override
        # engine_tenant_id in the auth context so every downstream engine sees
        # the correct tenant without each engine needing its own header logic.
        # Security: only allow tenants the user can actually access.
        active_tenant = request.headers.get("x-active-tenant-id") or request.headers.get("X-Active-Tenant-Id")
        if active_tenant and auth_ctx.can_access_tenant(active_tenant):
            import dataclasses as _dc
            auth_ctx = _dc.replace(auth_ctx, engine_tenant_id=active_tenant)

        # Set auth context on request state (for FastAPI dependencies)
        request.state.auth_context = auth_ctx

        # Inject X-Auth-Context into the actual request headers so BFF views
        # can read it via request.headers.get("X-Auth-Context").
        auth_header = auth_ctx.to_header_json()
        request.state.auth_header = auth_header

        # Mutate the scope headers list in-place so cached Headers objects see it
        request.scope["headers"].append((b"x-auth-context", auth_header.encode()))

        response = await call_next(request)
        return response

    async def _validate_token(self, raw_token: str) -> AuthContext | None:
        """Validate token against auth database using token_hint."""
        import asyncpg, json as _json

        def _j(val, default):
            """asyncpg returns JSONB as str — decode if needed."""
            if isinstance(val, str):
                try:
                    return _json.loads(val)
                except Exception:
                    return default
            return val if val is not None else default

        def _check_password(raw: str, encoded: str) -> bool:
            """Verify Django pbkdf2_sha256 hash without requiring Django settings."""
            import hashlib, base64
            parts = encoded.split("$")
            if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
                return False
            _, iterations_str, salt, b64hash = parts
            dk = hashlib.pbkdf2_hmac("sha256", raw.encode(), salt.encode(), int(iterations_str))
            return base64.b64encode(dk).decode() == b64hash

        pool = await self._get_pool()

        hint = raw_token[:8]

        # Query sessions with matching token_hint
        rows = await pool.fetch(
            """
            SELECT
                s.id, s.token, s.user_id, s.permissions_cache, s.scope_cache,
                u.email, u.customer_id,
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
            if _check_password(raw_token, row["token"]):
                scope = _j(row["scope_cache"], {})
                if not scope.get("engine_tenant_id"):
                    scope = await self._backfill_engine_tenant_id(pool, row["id"], scope)
                return AuthContext.from_session_cache(
                    user_id=row["user_id"],
                    email=row["email"],
                    role_name=row["role_name"] or "none",
                    role_level=row["role_level"] or 99,
                    role_scope_level=row["role_scope_level"] or "account",
                    permissions_cache=_j(row["permissions_cache"], []),
                    scope_cache=scope,
                    customer_id=str(row["customer_id"]) if row["customer_id"] else None,
                )

        # Fallback: try sessions without token_hint (old sessions created before
        # RBAC-01 added the column).  We do a full hash comparison here.
        # COALESCE in SQL ensures NULL permissions_cache / scope_cache columns
        # never reach Python as None — they default to empty list / empty object.
        rows = await pool.fetch(
            """
            SELECT
                s.id, s.token, s.user_id,
                COALESCE(s.permissions_cache, '[]'::jsonb)  AS permissions_cache,
                COALESCE(s.scope_cache,       '{}'::jsonb)  AS scope_cache,
                u.email, u.customer_id,
                r.name       AS role_name,
                r.level      AS role_level,
                r.scope_level AS role_scope_level
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
            if _check_password(raw_token, row["token"]):
                # Backfill token_hint fire-and-forget — do not block on failure
                try:
                    await pool.execute(
                        "UPDATE user_sessions SET token_hint = $1 WHERE id = $2",
                        hint,
                        row["id"],
                    )
                except Exception as _backfill_err:
                    logger.warning(
                        "token_hint backfill failed for session %s: %s",
                        row["id"],
                        _backfill_err,
                    )
                scope = _j(row["scope_cache"], {})
                if not scope.get("engine_tenant_id"):
                    scope = await self._backfill_engine_tenant_id(pool, row["id"], scope)
                return AuthContext.from_session_cache(
                    user_id=row["user_id"],
                    email=row["email"],
                    role_name=row["role_name"] or "none",
                    role_level=row["role_level"] or 99,
                    role_scope_level=row["role_scope_level"] or "account",
                    permissions_cache=_j(row["permissions_cache"], []),
                    scope_cache=scope,
                    customer_id=str(row["customer_id"]) if row["customer_id"] else None,
                )

        return None

    async def _backfill_engine_tenant_id(self, pool, session_id: int, scope: dict) -> dict:
        """Resolve a default engine_tenant_id for sessions that lack one.

        For platform-level sessions (scope_level="platform" / tenant_ids=None),
        we intentionally leave engine_tenant_id as None so the BFF can serve
        cross-tenant "All Tenants" views without a forced single-tenant scope.

        For tenant-scoped sessions, uses the first entry in tenant_ids.
        Updates scope_cache in-place so subsequent requests skip this lookup.
        """
        # Platform-level users have unrestricted access — do not force a tenant.
        # Returning scope as-is means engine_tenant_id stays None, which the BFF
        # handles via resolve_tenant_id()'s platform-level escape hatch.
        if scope.get("scope_level") == "platform" or scope.get("tenant_ids") is None:
            return scope

        tid = None
        if scope.get("tenant_ids"):
            tid = scope["tenant_ids"][0]
        else:
            try:
                row = await pool.fetchrow(
                    """
                    SELECT engine_tenant_id, id::text AS id_str
                    FROM tenant_management_tenants
                    ORDER BY created_at ASC
                    LIMIT 1
                    """
                )
                if row:
                    tid = row["engine_tenant_id"] or row["id_str"]
            except Exception as exc:
                logger.warning("engine_tenant_id backfill failed: %s", exc)

        if tid:
            scope = {**scope, "engine_tenant_id": tid}
            try:
                import json as _j2
                await pool.execute(
                    "UPDATE user_sessions SET scope_cache = $1::jsonb WHERE id = $2",
                    _j2.dumps(scope),
                    session_id,
                )
            except Exception as exc:
                logger.warning("scope_cache update failed for session %s: %s", session_id, exc)
        return scope

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
