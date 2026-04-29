# tenant_management/filters.py
from django.db.models import Q
from .models import Tenants
from user_auth.models import Roles

ALLOWED_FILTERS = {"status", "plan", "region"}
SEARCH_SUFFIX = "_search"
ALLOWED_LOOKUPS = {"iexact", "icontains", "istartswith", "gte", "lte", "gt", "lt"}


def user_has_developer_role(user):
    if not user or not user.is_authenticated:
        return False
    return Roles.objects.filter(
        userroles__user=user,
        name__iexact="developer"  # or however you identify it
    ).exists()


def build_tenant_query(params, user=None):
    base_query = Q()

    # Exact filters
    for param in ALLOWED_FILTERS:
        if param in params and params[param]:
            base_query &= Q(**{f"{param}__iexact": str(params[param]).strip()})

    # Search filters (field_search=value → field__icontains)
    for param, value in params.items():
        if param.endswith(SEARCH_SUFFIX) and value:
            field_name = param[: -len(SEARCH_SUFFIX)]
            if hasattr(Tenants, field_name):
                base_query &= Q(**{f"{field_name}__icontains": str(value).strip()})

    # Dynamic lookups (field__lookup=value)
    for param, value in params.items():
        if "__" in param and not param.endswith(SEARCH_SUFFIX):
            parts = param.split("__", 1)
            if len(parts) == 2:
                field, lookup = parts
                if (
                    hasattr(Tenants, field)
                    and lookup in ALLOWED_LOOKUPS
                    and value
                ):
                    base_query &= Q(**{param: value})

    queryset = Tenants.objects.filter(base_query)

    # Scoping: full access for developers, scoped otherwise
    if user and user.is_authenticated and not user_has_developer_role(user):
        tenant_ids = user.tenant_users.values_list("tenant_id", flat=True)
        queryset = queryset.filter(id__in=tenant_ids)

    return queryset