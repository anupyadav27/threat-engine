"""
Scope resolution for multi-tenant access: super_landlord, landlord, customer_admin,
group_admin, tenant role, tenant user.
Returns allowed_tenant_ids, allowed_customer_ids, is_super_landlord, capabilities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from user_auth.models import Users


ADMIN_ROLE_NAMES = frozenset({
    "super_landlord",
    "landlord",
    "customer_admin",
    "group_admin",
    "tenant",
})


def _role_names(user: "Users") -> set[str]:
    if not user or not getattr(user, "pk", None):
        return set()
    from user_auth.models import UserRoles
    return set(
        UserRoles.objects.filter(user=user)
        .values_list("role__name", flat=True)
    )


def _tenant_ids_from_tenant_users(user: "Users") -> list[str]:
    if not user or not getattr(user, "pk", None):
        return []
    from tenant_management.models import TenantUsers
    return list(
        TenantUsers.objects.filter(user=user).values_list("tenant_id", flat=True).distinct()
    )


def _admin_scope_rows(user: "Users"):
    from user_auth.models import UserAdminScope
    return list(UserAdminScope.objects.filter(user=user).select_related("role"))


def get_allowed_scope(user: "Users") -> dict:
    """
    Resolve allowed scope for user.
    Returns:
        allowed_tenant_ids: list of tenant ids (None = all)
        allowed_customer_ids: list of customer ids (None = all, [] when no customers)
        is_super_landlord: bool
        capabilities: list of str, e.g. can_manage_users, can_manage_tenants
    """
    out = {
        "allowed_tenant_ids": None,
        "allowed_customer_ids": [],
        "allowed_landlord_ids": None,
        "is_super_landlord": False,
        "roles": [],
        "capabilities": [],
    }
    if not user or not getattr(user, "pk", None):
        return out

    roles = _role_names(user)
    out["roles"] = list(roles)

    if "super_landlord" in roles:
        out["is_super_landlord"] = True
        out["allowed_tenant_ids"] = None  # all
        out["allowed_customer_ids"] = None
        out["capabilities"] = [
            "can_manage_users",
            "can_manage_tenants",
            "can_manage_landlords",
            "can_access_settings",
            "can_access_dashboard",
            "can_access_assets",
            "can_access_threats",
            "can_access_secops",
            "can_access_reports",
            "can_access_compliance",
            "can_access_policies",
        ]
        return out

    scopes = _admin_scope_rows(user)
    customer_ids = []
    tenant_ids = []

    for s in scopes:
        if s.scope_type == "customer":
            customer_ids.append(s.scope_id)
        elif s.scope_type == "tenant":
            tenant_ids.append(s.scope_id)

    if "landlord" in roles:
        # Landlord: N customers (or N tenants if no customers). We use tenant scope for now.
        if not tenant_ids and not customer_ids:
            pass  # no scope rows
        else:
            out["allowed_customer_ids"] = list(dict.fromkeys(customer_ids))
            out["allowed_tenant_ids"] = list(dict.fromkeys(tenant_ids))
        out["capabilities"] = [
            "can_manage_tenants",
            "can_access_settings",
            "can_access_dashboard",
            "can_access_assets",
            "can_access_threats",
            "can_access_secops",
            "can_access_reports",
            "can_access_compliance",
            "can_access_policies",
        ]
        return out

    if "customer_admin" in roles:
        # One customer; we use tenant scope for now. Single tenant = single "customer".
        if len(tenant_ids) >= 1:
            out["allowed_tenant_ids"] = tenant_ids[:1]
        if len(customer_ids) >= 1:
            out["allowed_customer_ids"] = customer_ids[:1]
        out["capabilities"] = [
            "can_manage_tenants",
            "can_access_settings",
            "can_access_dashboard",
            "can_access_assets",
            "can_access_threats",
            "can_access_secops",
            "can_access_reports",
            "can_access_compliance",
            "can_access_policies",
        ]
        return out

    if "group_admin" in roles:
        out["allowed_customer_ids"] = list(dict.fromkeys(customer_ids))
        out["allowed_tenant_ids"] = list(dict.fromkeys(tenant_ids))
        out["capabilities"] = [
            "can_manage_tenants",
            "can_access_settings",
            "can_access_dashboard",
            "can_access_assets",
            "can_access_threats",
            "can_access_secops",
            "can_access_reports",
            "can_access_compliance",
            "can_access_policies",
        ]
        return out

    if "tenant" in roles:
        # Tenant role: single tenant
        if len(tenant_ids) >= 1:
            out["allowed_tenant_ids"] = tenant_ids[:1]
        out["capabilities"] = [
            "can_access_settings",
            "can_access_dashboard",
            "can_access_assets",
            "can_access_threats",
            "can_access_secops",
            "can_access_reports",
            "can_access_compliance",
            "can_access_policies",
        ]
        return out

    # Tenant user: TenantUsers only
    tu_ids = _tenant_ids_from_tenant_users(user)
    out["allowed_tenant_ids"] = tu_ids
    out["capabilities"] = [
        "can_access_dashboard",
        "can_access_assets",
        "can_access_threats",
        "can_access_secops",
        "can_access_reports",
        "can_access_compliance",
        "can_access_policies",
    ]
    return out


def tenant_in_scope(tenant_id: str, scope: dict) -> bool:
    if scope.get("is_super_landlord"):
        return True
    allowed = scope.get("allowed_tenant_ids")
    if allowed is None:
        return True
    return tenant_id in allowed


def customer_in_scope(customer_id: str, scope: dict) -> bool:
    if scope.get("is_super_landlord"):
        return True
    allowed = scope.get("allowed_customer_ids")
    if allowed is None:
        return True
    return customer_id in allowed


def has_capability(scope: dict, capability: str) -> bool:
    if scope.get("is_super_landlord"):
        return True
    return capability in (scope.get("capabilities") or [])
