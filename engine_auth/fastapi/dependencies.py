"""
FastAPI dependencies for RBAC.

Usage:
    from engine_auth.fastapi import require_permission, get_auth_context

    @app.get("/api/v1/threats")
    async def list_threats(
        tenant_id: str,
        ctx: AuthContext = Depends(get_auth_context),
    ):
        ...

    # Or with permission check:
    @app.get("/api/v1/threats", dependencies=[Depends(require_permission("account:threats:read"))])
    async def list_threats(tenant_id: str, request: Request):
        ...
"""

from __future__ import annotations

import json
import logging
from fastapi import Request, HTTPException
from engine_auth.core.models import AuthContext

logger = logging.getLogger(__name__)


async def get_auth_context(request: Request) -> AuthContext:
    """
    FastAPI dependency: extract AuthContext from request.

    The AuthContext is set by AuthMiddleware (from cookie validation)
    or from X-Auth-Context header (forwarded by API gateway).
    """
    # First check if middleware already set it
    ctx = getattr(request.state, "auth_context", None)
    if ctx:
        return ctx

    # Try X-Auth-Context header (forwarded by gateway to engines)
    header = request.headers.get("X-Auth-Context")
    if header:
        try:
            data = json.loads(header)
            ctx = AuthContext.from_dict(data)
            request.state.auth_context = ctx
            return ctx
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Invalid X-Auth-Context header: %s", e)
            raise HTTPException(status_code=401, detail="Invalid auth context")

    raise HTTPException(status_code=401, detail="Authentication required")


def require_permission(permission_key: str):
    """
    FastAPI dependency factory: require a specific permission.

    Usage:
        @app.get("/threats", dependencies=[Depends(require_permission("account:threats:read"))])
    """

    async def _check(request: Request):
        ctx = await get_auth_context(request)

        # Check permission
        if not ctx.has_permission(permission_key):
            logger.info(
                "Permission denied: user=%s role=%s missing %s",
                ctx.user_id, ctx.role, permission_key,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: requires {permission_key}",
            )

        # Check scope from query params
        tenant_id = request.query_params.get("tenant_id")
        account_id = request.query_params.get("account_id")
        org_id = request.query_params.get("org_id")

        if org_id and not ctx.can_access_org(org_id):
            raise HTTPException(status_code=403, detail="Access denied for this organization")

        if tenant_id and not ctx.can_access_tenant(tenant_id):
            raise HTTPException(status_code=403, detail="Access denied for this tenant")

        if account_id and not ctx.can_access_account(account_id):
            raise HTTPException(status_code=403, detail="Access denied for this account")

        return ctx

    return _check
