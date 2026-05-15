"""Shared DRF permission classes for org-boundary enforcement (auth-B4).

OrgScopedPermission enforces that non-platform_admin users can only access
objects belonging to their own customer_id organisation.  It is applied to
TenantViewSet and any ViewSet that handles Tenant, CloudAccount, or User
objects accessible to org_admin.

Usage:
    from shared.permissions import OrgScopedPermission

    class TenantViewSet(viewsets.GenericViewSet):
        permission_classes = [HasPermission("tenants:read"), OrgScopedPermission]
"""
from __future__ import annotations

from rest_framework.permissions import BasePermission


class OrgScopedPermission(BasePermission):
    """Object-level permission: restrict access to objects within the same org.

    - ``platform_admin`` (role level 1): unconditionally allowed — sees all orgs.
    - All other roles: allowed only when ``obj.customer_id`` matches
      ``request.user.customer_id``.
    - If the object has no ``customer_id`` attribute the check is skipped and
      access is allowed (the view's queryset scoping is the primary boundary).

    This permission must be used alongside a queryset that already applies
    ``enforce_org_boundary()`` — OrgScopedPermission adds a defence-in-depth
    check at the object retrieval layer (has_object_permission) to prevent
    direct-object-access bypasses (e.g. /api/v1/tenants/<uuid>/ with a
    foreign customer_id).
    """

    def has_permission(self, request, view) -> bool:
        # List/create access is controlled by HasPermission; always pass here
        # so that has_object_permission can do the fine-grained check.
        return True

    def has_object_permission(self, request, view, obj) -> bool:
        """Return True if the user may access *obj*.

        platform_admin bypasses the check.  For all other roles, *obj* must
        carry a ``customer_id`` that matches the authenticated user's own
        ``customer_id``.
        """
        user = request.user

        # platform_admin: unrestricted cross-org access
        if getattr(user, "role", None) == "platform_admin":
            return True

        # Role-check via UserRoles (authoritative source — not a spoofable header)
        try:
            from user_auth.models import UserRoles

            ur = (
                UserRoles.objects.filter(user=user)
                .select_related("role")
                .order_by("role__level")
                .first()
            )
            if ur and ur.role and ur.role.name == "platform_admin":
                return True
        except Exception:
            pass

        # Objects without customer_id are not org-scoped at the object level;
        # rely on queryset scoping as the primary boundary.
        if not hasattr(obj, "customer_id"):
            return True

        user_customer_id = getattr(user, "customer_id", None)
        return obj.customer_id == user_customer_id
