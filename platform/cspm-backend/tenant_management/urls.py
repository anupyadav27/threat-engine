from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    TenantViewSet,
    TenantIDPConfigListCreateView,
    TenantIDPConfigDetailView,
    TenantIDPConfigActivateView,
    TenantIDPByDomainView,
)

router = DefaultRouter()
router.register(r"tenants", TenantViewSet, basename="tenant")

urlpatterns = [
    # Explicit paths must come BEFORE the router include — the DRF router
    # registers tenants/<pk>/ which would otherwise swallow "idp-by-domain"
    # as a pk lookup and return 404.
    path("tenants/idp-by-domain/", TenantIDPByDomainView.as_view(), name="idp_by_domain"),
    path("tenants/idp/", TenantIDPConfigListCreateView.as_view(), name="idp_config_list_create"),
    path("tenants/idp/<str:pk>/", TenantIDPConfigDetailView.as_view(), name="idp_config_detail"),
    path("tenants/idp/<str:pk>/activate/", TenantIDPConfigActivateView.as_view(), name="idp_config_activate"),

    # Router last
    path("", include(router.urls)),
]
