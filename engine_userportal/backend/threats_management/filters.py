from django.db.models import Q
from .models import Threat

ALLOWED_FILTERS = {
    "tenant_id", "severity", "status", "name"
}
SEARCH_SUFFIX = "_search"
ALLOWED_LOOKUPS = {"iexact", "icontains", "istartswith", "gte", "lte", "gt", "lt"}

def build_threat_query(params):
    """Builds Q-filtered queryset for Threats matching Node.js behavior"""
    base_query = Q()

    for param in ALLOWED_FILTERS:
        if param in params and params[param]:
            base_query &= Q(**{f"{param}__iexact": str(params[param]).strip()})

    for param, value in params.items():
        if param.endswith(SEARCH_SUFFIX) and value:
            field_name = param[: -len(SEARCH_SUFFIX)]
            if hasattr(Threat, field_name):
                base_query &= Q(**{f"{field_name}__icontains": str(value).strip()})

    for param, value in params.items():
        if "__" in param and not param.endswith(SEARCH_SUFFIX):
            parts = param.split("__", 1)
            if len(parts) == 2:
                field, lookup = parts
                if (
                    hasattr(Threat, field)
                    and lookup in ALLOWED_LOOKUPS
                    and value
                ):
                    base_query &= Q(**{param: value})

    return Threat.objects.filter(base_query)