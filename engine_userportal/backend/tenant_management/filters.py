# tenant_management/filters.py
from django.db.models import Q
from .models import Tenants
from user_auth.models import Roles

ALLOWED_FILTERS = {"status", "plan", "region"}
SEARCH_SUFFIX = "_search"
ALLOWED_LOOKUPS = {"iexact", "icontains", "istartswith", "gte", "lte", "gt", "lt"}


def user_has_developer_role(user):
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return Roles.objects.filter(
        userroles__user=user,
        name__iexact="developer",
    ).exists()


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
                if (
                    hasattr(Tenants, field)
                    and lookup in ALLOWED_LOOKUPS
                    and value
                ):
                    base_query &= Q(**{param: value})

    queryset = Tenants.objects.filter(base_query)

    if not user or not getattr(user, "pk", None):
        return queryset.none()

    if user_has_developer_role(user):
        return queryset

    from user_auth.utils.scope_utils import get_allowed_scope

    scope = get_allowed_scope(user)
    if scope.get("is_super_landlord"):
        return queryset
    allowed = scope.get("allowed_tenant_ids")
    if allowed is None:
        return queryset
    if not allowed:
        return queryset.none()
    return queryset.filter(id__in=allowed)