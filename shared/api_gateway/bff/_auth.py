"""
BFF auth helpers — read AuthContext from the X-Auth-Context header.

These helpers replace direct tenant_id: str = Query(...) parameters
in BFF view handlers. The tenant_id is resolved server-side from the
session, not accepted from the client query string.
"""

from __future__ import annotations

import json
import logging
from typing import Optional, List

from fastapi import Request, HTTPException
from engine_auth.core.models import AuthContext

logger = logging.getLogger("api-gateway.bff.auth")


def _parse_auth_context(request: Request) -> Optional[AuthContext]:
    """Parse X-Auth-Context header into AuthContext. Returns None if missing/invalid."""
    raw = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    if not raw:
        return None
    try:
        return AuthContext.from_dict(json.loads(raw))
    except Exception as exc:
        logger.warning("BFF: failed to parse X-Auth-Context: %s", exc)
        return None


def resolve_tenant_id(request: Request) -> Optional[str]:
    """
    Resolve engine_tenant_id from the authenticated session.

    Priority:
      1. AuthContext.engine_tenant_id (set after DI-02)
      2. AuthContext.tenant_ids[0] (fallback for old sessions)
      3. None for platform-level users (All Tenants view — no filter)
      4. Raise HTTP 401/400 for non-platform users with no tenant

    Never reads tenant_id from query string.
    Callers pass the result as an httpx query param; httpx silently drops
    None values, so engines receive no tenant_id filter for platform-level
    All Tenants requests — returning all data scoped by RBAC.
    """
    ctx = _parse_auth_context(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    # The frontend persists the active tenant client-side and forwards it via
    # this header on every gateway call. For platform-level users, this is the
    # only signal that reflects the dropdown selection — Django session scope
    # backfills engine_tenant_id to tenants[0] regardless of what the user picked.
    # For tenant-scoped users, the header just confirms what's already in scope.
    # Either way, the explicit selection wins over the cached scope value.
    active = request.headers.get("x-active-tenant-id") or request.headers.get(
        "X-Active-Tenant-Id"
    )
    if active:
        return active

    if ctx.engine_tenant_id:
        return ctx.engine_tenant_id

    if ctx.tenant_ids and len(ctx.tenant_ids) > 0:
        return ctx.tenant_ids[0]

    if ctx.is_platform_level():
        return None

    raise HTTPException(
        status_code=400,
        detail="No active tenant in session. Select a tenant first.",
    )


def resolve_tenant_id_optional(request: Request) -> Optional[str]:
    """
    Like resolve_tenant_id but returns None instead of raising.
    Used for platform_admin views where tenant_id is optional.
    """
    try:
        return resolve_tenant_id(request)
    except HTTPException:
        return None


def account_filter(request: Request) -> Optional[List[str]]:
    """
    Return the list of account_ids this user is restricted to, or None if unrestricted.

    Use in SQL queries as:
        WHERE ($1::text[] IS NULL OR account_id = ANY($1))

    where $1 = account_filter(request)
    """
    ctx = _parse_auth_context(request)
    if ctx is None:
        return None
    return ctx.account_ids  # None = unrestricted, list = restricted


def require_tenant_access(request: Request, tenant_id: str) -> None:
    """
    Assert that the authenticated user can access the given tenant_id.
    Raises HTTP 403 if the tenant is outside the user's scope.

    Platform admins (tenant_ids=None) always pass.
    """
    ctx = _parse_auth_context(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not ctx.can_access_tenant(tenant_id):
        raise HTTPException(status_code=403, detail="Access to this tenant is not permitted")
