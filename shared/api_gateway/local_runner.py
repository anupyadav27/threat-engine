"""
Local-dev runner for the API gateway.

Wraps `main:app` with an X-Auth-Context injector that synthesizes a
platform_admin context when no auth header is present. This lets the
gateway run on a laptop without DB connectivity to the userportal DB
(which would normally be required by AuthMiddleware to validate the
access_token cookie).

Run with:
    LOCAL_DEV_BYPASS_AUTH=1 \
    uvicorn local_runner:app --host 0.0.0.0 --port 8000

If LOCAL_DEV_BYPASS_AUTH is not set to "1", behaves identically to
`main:app` (no synthesized header).
"""

import json
import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

_BYPASS = os.getenv("LOCAL_DEV_BYPASS_AUTH") == "1"

# Monkey-patch AuthContext.has_permission to always grant in local-dev mode.
# Must be done BEFORE main is imported so engines that capture
# `has_permission` as a closure see the patched version.
if _BYPASS:
    from engine_auth.core import models as _auth_models

    def _grant_all(self, key):  # noqa: ARG001
        return True

    def _grant_all_any(self, *keys):  # noqa: ARG001
        return True

    def _grant_all_feature(self, feature, action="read"):  # noqa: ARG001
        return True

    _auth_models.AuthContext.has_permission = _grant_all
    _auth_models.AuthContext.has_any_permission = _grant_all_any
    _auth_models.AuthContext.has_all_permissions = _grant_all_any
    _auth_models.AuthContext.has_feature_access = _grant_all_feature
    _auth_models.AuthContext.can_access_tenant = lambda self, tid: True

from main import app  # re-export the existing FastAPI app  # noqa: E402

_TENANT = os.getenv("LOCAL_DEV_TENANT_ID", "default-tenant")
_USER_ID = os.getenv("LOCAL_DEV_USER_ID", "local-dev")
_EMAIL = os.getenv("LOCAL_DEV_EMAIL", "local-dev@example.com")


_LOCAL_DEV_PERMISSIONS = [
    "account:threats:read",
    "ai_security:read", "ai_security:write",
    "billing:read", "billing:write",
    "check:read", "check:write",
    "ciem:read", "ciem:write",
    "cloud_accounts:read", "cloud_accounts:write",
    "compliance:read", "compliance:write",
    "container_security:read", "container_security:write",
    "cwpp:read", "cwpp:write",
    "database_security:read", "database_security:write",
    "datasec:read", "datasec:write",
    "discoveries:read", "discoveries:write",
    "encryption:read", "encryption:write",
    "iam:read", "iam:write",
    "inventory:read", "inventory:write",
    "network:read", "network:write",
    "platform:admin",
    "risk:read", "risk:write",
    "scans:create", "scans:read", "scans:write",
    "secops:read", "secops:write",
    "threat:read", "threat:write",
    "vulnerability:read", "vulnerability:write",
]


def _synthetic_ctx_header() -> str:
    return json.dumps({
        "user_id": _USER_ID,
        "email": _EMAIL,
        "role": "platform_admin",
        "level": 1,
        "scope_level": "platform",
        "permissions": _LOCAL_DEV_PERMISSIONS,
        "org_ids": None,
        "tenant_ids": None,
        "account_ids": None,
        "engine_tenant_id": _TENANT,
    })


class LocalDevAuthInjector(BaseHTTPMiddleware):
    """If no X-Auth-Context is present, inject a platform_admin context.

    Must be added LAST (so it runs FIRST on inbound requests, before
    AuthMiddleware). AuthMiddleware sees the header and trusts it
    without DB lookup.
    """

    async def dispatch(self, request: Request, call_next):
        existing = (
            request.headers.get("x-auth-context")
            or request.headers.get("X-Auth-Context")
        )
        if not existing:
            header_val = _synthetic_ctx_header()
            request.scope["headers"].append(
                (b"x-auth-context", header_val.encode())
            )
        return await call_next(request)


if _BYPASS:
    app.add_middleware(LocalDevAuthInjector)


# ── Local-dev API docs (Swagger + ReDoc) ────────────────────────────────────
# main.py's route_requests middleware intercepts every path that doesn't start
# with /gateway/, /api/v1/views/, or /argo/, so FastAPI's auto-generated /docs
# never reaches the FastAPI router. We re-mount Swagger UI and the OpenAPI
# schema under /gateway/* so the proxy middleware lets them through.
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402


@app.get("/gateway/openapi.json", include_in_schema=False)
async def _local_openapi():
    return JSONResponse(app.openapi())


@app.get("/gateway/docs", include_in_schema=False)
async def _local_swagger_ui():
    return get_swagger_ui_html(
        openapi_url="/gateway/openapi.json",
        title="CSPM API Gateway — local",
    )


@app.get("/gateway/redoc", include_in_schema=False)
async def _local_redoc():
    return get_redoc_html(
        openapi_url="/gateway/openapi.json",
        title="CSPM API Gateway — local (ReDoc)",
    )
