"""RBAC utility — org-boundary enforcement for Django views.

Used by TenantViewSet, GroupViewSet, and user management views to ensure
org_admin cannot access resources from other customer organisations.

AC7 (auth-B4): enforce_org_boundary() is the single canonical implementation.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.db.models import QuerySet

if TYPE_CHECKING:
    from user_auth.models import Users

logger = logging.getLogger(__name__)

# Role name that bypasses the org filter (sees all orgs).
_PLATFORM_ADMIN = "platform_admin"


def _primary_role_name(user: "Users") -> str | None:
    """Return the highest-privilege role name for the user, or None.

    Lowest ``level`` integer = highest privilege, so we order ascending.
    """
    from user_auth.models import UserRoles

    ur = (
        UserRoles.objects.filter(user=user)
        .select_related("role")
        .order_by("role__level")
        .first()
    )
    return ur.role.name if ur and ur.role else None


def enforce_org_boundary(user: "Users", queryset: QuerySet) -> QuerySet:
    """Filter *queryset* by the user's ``customer_id`` unless user is platform_admin.

    Args:
        user: Authenticated Users instance from ``request.user``.
        queryset: An unfiltered Django ORM queryset whose model has a
            ``customer_id`` column (Tenants, CsmGroups, etc.).

    Returns:
        A queryset scoped to the user's org, or the full queryset for
        platform_admin.

    Raises:
        PermissionError: If the user is not platform_admin and has no
            ``customer_id`` (indicates auth-A1 backfill migration has not
            been applied or the user account is incomplete).
    """
    role = _primary_role_name(user)

    if role == _PLATFORM_ADMIN:
        # platform_admin: no org boundary — sees everything
        return queryset

    customer_id = getattr(user, "customer_id", None)
    if not customer_id:
        logger.error(
            "enforce_org_boundary: user %s has no customer_id — "
            "returning empty queryset to fail safe (run auth-A1 backfill)",
            getattr(user, "id", "?"),
        )
        # Fail safe: return nothing rather than leak data
        return queryset.none()

    return queryset.filter(customer_id=customer_id)


def is_platform_admin(user: "Users") -> bool:
    """Return True iff the user's highest-privilege role is platform_admin."""
    return _primary_role_name(user) == _PLATFORM_ADMIN
