"""
Django REST Framework permission classes for RBAC.

Usage in views:
    from engine_auth.django import RequirePermission

    class ThreatListView(APIView):
        authentication_classes = [CookieTokenAuthentication]
        permission_classes = [RequirePermission("account:threats:read")]

    # Or for multiple permissions:
    class ThreatUpdateView(APIView):
        permission_classes = [RequirePermission("account:threats:write")]
"""

from __future__ import annotations

import logging
from rest_framework.permissions import BasePermission

logger = logging.getLogger(__name__)


def RequirePermission(permission_key: str):
    """
    Factory that returns a DRF permission class requiring a specific permission.

    Checks both:
    1. Permission key exists in user's cached permissions
    2. Resource scope (org/tenant/account) from request params is in user's scope

    Scope IDs are extracted from:
    - URL kwargs: tenant_id, account_id, org_id
    - Query params: tenant_id, account_id, org_id
    - Request body (POST): tenant_id, account_id, org_id
    """

    class _RequirePermission(BasePermission):
        _permission_key = permission_key

        def has_permission(self, request, view):
            ctx = getattr(request, "auth_context", None)
            if not ctx:
                logger.warning(
                    "RequirePermission(%s): no auth_context on request",
                    permission_key,
                )
                return False

            # 1. Check permission
            if not ctx.has_permission(permission_key):
                logger.info(
                    "Permission denied: user=%s role=%s missing %s",
                    ctx.user_id, ctx.role, permission_key,
                )
                return False

            # 2. Check scope
            org_id = self._extract_param(request, view, "org_id")
            tenant_id = self._extract_param(request, view, "tenant_id")
            account_id = self._extract_param(request, view, "account_id")

            if org_id and not ctx.can_access_org(org_id):
                logger.info(
                    "Scope denied: user=%s cannot access org=%s",
                    ctx.user_id, org_id,
                )
                return False

            if tenant_id and not ctx.can_access_tenant(tenant_id):
                logger.info(
                    "Scope denied: user=%s cannot access tenant=%s",
                    ctx.user_id, tenant_id,
                )
                return False

            if account_id and not ctx.can_access_account(account_id):
                logger.info(
                    "Scope denied: user=%s cannot access account=%s",
                    ctx.user_id, account_id,
                )
                return False

            return True

        def _extract_param(self, request, view, param_name: str) -> str | None:
            """Extract a scope parameter from URL kwargs, query params, or body."""
            # URL kwargs (e.g., /api/tenants/<tenant_id>/threats/)
            if hasattr(view, "kwargs") and view.kwargs:
                val = view.kwargs.get(param_name)
                if val:
                    return str(val)

            # Query params (e.g., ?tenant_id=xxx)
            val = request.query_params.get(param_name)
            if val:
                return str(val)

            # Request body (for POST/PUT)
            if hasattr(request, "data") and isinstance(request.data, dict):
                val = request.data.get(param_name)
                if val:
                    return str(val)

            return None

    _RequirePermission.__name__ = f"Require_{permission_key.replace(':', '_')}"
    _RequirePermission.__qualname__ = _RequirePermission.__name__
    return _RequirePermission


class IsAuthenticated(BasePermission):
    """Simple check: is auth_context present? (replaces DRF's IsAuthenticated)."""

    def has_permission(self, request, view):
        return getattr(request, "auth_context", None) is not None


class IsPlatformAdmin(BasePermission):
    """Check if user is platform_admin (level 1)."""

    def has_permission(self, request, view):
        ctx = getattr(request, "auth_context", None)
        return ctx is not None and ctx.is_platform_level()
