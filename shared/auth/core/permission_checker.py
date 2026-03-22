"""
Permission checker — utility functions for checking permissions and scope.

Used by both Django and FastAPI permission classes.
"""

from __future__ import annotations

from .models import AuthContext


def check_permission(ctx: AuthContext, permission_key: str) -> bool:
    """Check if the auth context has a specific permission."""
    if not ctx:
        return False
    return ctx.has_permission(permission_key)


def check_scope(
    ctx: AuthContext,
    org_id: str | None = None,
    tenant_id: str | None = None,
    account_id: str | None = None,
) -> bool:
    """
    Check if the auth context can access the given resource scope.

    At least one of org_id, tenant_id, account_id should be provided.
    Returns True if user can access ALL provided scope IDs.
    """
    if not ctx:
        return False

    if org_id and not ctx.can_access_org(org_id):
        return False
    if tenant_id and not ctx.can_access_tenant(tenant_id):
        return False
    if account_id and not ctx.can_access_account(account_id):
        return False

    return True


def check_permission_and_scope(
    ctx: AuthContext,
    permission_key: str,
    org_id: str | None = None,
    tenant_id: str | None = None,
    account_id: str | None = None,
) -> bool:
    """Combined permission + scope check (the most common pattern)."""
    return (
        check_permission(ctx, permission_key)
        and check_scope(ctx, org_id=org_id, tenant_id=tenant_id, account_id=account_id)
    )


def get_scope_filter(ctx: AuthContext) -> dict:
    """
    Get a filter dict for Django ORM queries based on user's scope.

    Returns dict like:
        {"tenant_id__in": ["t1", "t2"]}
    or empty dict for unrestricted users.

    Usage:
        qs = ThreatFindings.objects.filter(**get_scope_filter(ctx))
    """
    filters = {}

    if ctx.org_ids is not None:
        filters["organization_id__in"] = ctx.org_ids

    if ctx.tenant_ids is not None:
        filters["tenant_id__in"] = ctx.tenant_ids

    if ctx.account_ids is not None:
        filters["account_id__in"] = ctx.account_ids

    return filters
