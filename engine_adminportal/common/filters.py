"""
Custom filters for admin portal.
"""
from django_filters import rest_framework as filters


class TenantFilter(filters.FilterSet):
    """Filter for tenant queries."""
    status = filters.CharFilter(field_name='status', lookup_expr='iexact')
    created_after = filters.DateTimeFilter(field_name='created_at', lookup_expr='gte')
    created_before = filters.DateTimeFilter(field_name='created_at', lookup_expr='lte')


class UserFilter(filters.FilterSet):
    """Filter for user queries."""
    is_active = filters.BooleanFilter(field_name='is_active')
    role = filters.CharFilter(field_name='roles__name', lookup_expr='iexact')
    tenant_id = filters.CharFilter(field_name='tenant_users__tenant_id', lookup_expr='exact')
