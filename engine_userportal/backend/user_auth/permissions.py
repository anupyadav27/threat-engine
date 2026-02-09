"""
DRF permissions: TenantScoped.
Requires authenticated user; validates tenant_id (and optionally customer_id)
against get_allowed_scope; 403 if invalid. Sets request.tenant_id, request.customer_id,
request.scope for downstream use.
"""

from rest_framework import permissions

from user_auth.utils.scope_utils import get_allowed_scope, tenant_in_scope, customer_in_scope


def _get_param(request, name):
    v = request.query_params.get(name)
    if v is not None:
        return v
    data = getattr(request, "data", None)
    if isinstance(data, dict):
        return data.get(name)
    return None


class TenantScoped(permissions.BasePermission):
    """
    Require authenticated user and validate tenant_id / customer_id from
    query_params or JSON body against user's allowed scope.
    Sets request.tenant_id, request.customer_id, request.scope.
    """

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not getattr(user, "pk", None):
            return False

        scope = get_allowed_scope(user)
        request.scope = scope

        tenant_id = _get_param(request, "tenant_id")
        customer_id = _get_param(request, "customer_id")

        if scope.get("is_super_landlord"):
            request.tenant_id = tenant_id
            request.customer_id = customer_id
            return True

        if tenant_id and not tenant_in_scope(str(tenant_id), scope):
            return False
        if customer_id and not customer_in_scope(str(customer_id), scope):
            return False

        request.tenant_id = tenant_id
        request.customer_id = customer_id
        return True


class TenantScopedRequiredTenant(TenantScoped):
    """
    Like TenantScoped but also requires tenant_id to be present (for views that
    always operate on a tenant, e.g. inventory, threats).
    """

    def has_permission(self, request, view):
        if not _get_param(request, "tenant_id"):
            return False
        return super().has_permission(request, view)
