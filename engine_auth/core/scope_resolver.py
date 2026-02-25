"""
Scope resolver — resolves permissions and scope from database at login time.

These functions are called ONCE at login and the results are cached in
user_sessions.permissions_cache and user_sessions.scope_cache.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass  # avoid circular imports; we use apps.get_model() pattern


def resolve_permissions(user) -> list[str]:
    """
    Resolve all permission keys for a user based on their role(s).

    Returns list of permission key strings like:
        ["platform:orgs:read", "org:users:write", "account:threats:read", ...]
    """
    from user_auth.models import RolePermissions, UserRoles

    # Get all role IDs for this user
    role_ids = list(
        UserRoles.objects.filter(user=user).values_list("role_id", flat=True)
    )
    if not role_ids:
        return []

    # Get all permission keys for these roles
    perms = list(
        RolePermissions.objects.filter(role_id__in=role_ids)
        .values_list("permission__key", flat=True)
        .distinct()
    )
    return sorted(perms)


def resolve_scope(user) -> dict:
    """
    Resolve scope (which orgs/tenants/accounts user can access).

    Returns dict like:
        {
            "org_ids": ["org-uuid-1", "org-uuid-2"] or None (unrestricted),
            "tenant_ids": [...] or None,
            "account_ids": [...] or None,
        }

    Rules:
        - platform_admin: all None (unrestricted)
        - org_admin: org_ids from scope, tenant_ids resolved from org's tenants
        - group_admin: whatever is in user_admin_scope
        - tenant_admin: tenant_ids from scope, account_ids resolved from tenant's accounts
        - account_admin: account_ids from scope
    """
    from user_auth.models import UserRoles, UserAdminScope

    # Get the user's primary role (highest level = lowest number)
    user_role = (
        UserRoles.objects.filter(user=user)
        .select_related("role")
        .order_by("role__level")
        .first()
    )

    if not user_role:
        return {"org_ids": [], "tenant_ids": [], "account_ids": []}

    role = user_role.role

    # Platform admin — unrestricted
    if role.scope_level == "platform":
        return {"org_ids": None, "tenant_ids": None, "account_ids": None}

    # Get all scope entries for this user
    scopes = list(UserAdminScope.objects.filter(user=user))

    org_ids = [s.scope_id for s in scopes if s.scope_type == "organization"]
    tenant_ids = [s.scope_id for s in scopes if s.scope_type == "tenant"]
    account_ids = [s.scope_id for s in scopes if s.scope_type == "account"]

    # Org-level roles: resolve tenants from org's tenants
    if role.scope_level == "organization" and org_ids:
        try:
            from tenant_management.models import Tenants
            org_tenant_ids = list(
                Tenants.objects.filter(organization_id__in=org_ids)
                .values_list("id", flat=True)
            )
            # Merge explicit tenant scopes with org-resolved tenants
            tenant_ids = list(set(tenant_ids + org_tenant_ids))
        except (ImportError, Exception):
            pass

    # Tenant-level roles: resolve accounts from tenant's accounts
    # (accounts are in the onboarding DB — we resolve what we can)
    # For now, tenant_admin gets access to all accounts under their tenants
    # via scope check on tenant_id (account → tenant FK in onboarding DB)

    return {
        "org_ids": org_ids or None if role.scope_level in ("platform",) else (org_ids or []),
        "tenant_ids": tenant_ids or None if role.scope_level in ("platform",) else (tenant_ids or []),
        "account_ids": account_ids or None if role.scope_level in ("platform", "organization", "tenant") else (account_ids or []),
    }


def resolve_role_info(user) -> dict:
    """
    Get the user's primary role name, level, and scope_level.

    Returns dict: {"name": "org_admin", "level": 2, "scope_level": "organization"}
    """
    from user_auth.models import UserRoles

    user_role = (
        UserRoles.objects.filter(user=user)
        .select_related("role")
        .order_by("role__level")
        .first()
    )
    if not user_role:
        return {"name": "none", "level": 99, "scope_level": "account"}

    return {
        "name": user_role.role.name,
        "level": user_role.role.level,
        "scope_level": user_role.role.scope_level,
    }
