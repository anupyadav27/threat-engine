"""Tenant queryset filtering — role-aware scoping with customer_id org boundary."""
from django.db.models import Q

from .models import Tenants

ALLOWED_FILTERS = {"status", "plan", "region"}
SEARCH_SUFFIX = "_search"
ALLOWED_LOOKUPS = {"iexact", "icontains", "istartswith", "gte", "lte", "gt", "lt"}


def _role_name(user) -> str | None:
    """Return the highest-privilege role name for the user, or None."""
    from user_auth.models import UserRoles
    ur = (
        UserRoles.objects.filter(user=user)
        .select_related("role")
        .order_by("role__level")
        .first()
    )
    return ur.role.name if ur and ur.role else None


def build_tenant_query(params, user=None):
    base_query = Q()

    for param in ALLOWED_FILTERS:
        if param in params and params[param]:
            base_query &= Q(**{f"{param}__iexact": str(params[param]).strip()})

    for param, value in params.items():
        if param.endswith(SEARCH_SUFFIX) and value:
            field_name = param[: -len(SEARCH_SUFFIX)]
            if hasattr(Tenants, field_name):
                base_query &= Q(**{f"{field_name}__icontains": str(value).strip()})

    for param, value in params.items():
        if "__" in param and not param.endswith(SEARCH_SUFFIX):
            parts = param.split("__", 1)
            if len(parts) == 2:
                field, lookup = parts
                if hasattr(Tenants, field) and lookup in ALLOWED_LOOKUPS and value:
                    base_query &= Q(**{param: value})

    if not user or not getattr(user, "is_authenticated", False):
        return Tenants.objects.none()

    role = _role_name(user)

    if role == "platform_admin":
        # Full visibility across all orgs
        return Tenants.objects.filter(base_query)

    if role == "org_admin":
        # Scoped to own org via customer_id
        customer_id = getattr(user, "customer_id", None) or str(user.id)
        return Tenants.objects.filter(base_query, customer_id=customer_id)

    # tenant_admin / analyst / viewer — scoped to explicit membership only
    tenant_ids = user.tenant_users.filter(is_active=True).values_list("tenant_id", flat=True)
    return Tenants.objects.filter(base_query, id__in=tenant_ids)
