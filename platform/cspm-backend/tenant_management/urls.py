from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    TenantViewSet,
    TenantIDPConfigListCreateView,
    TenantIDPConfigDetailView,
    TenantIDPConfigActivateView,
    TenantIDPByDomainView,
    ResyncTenantView,
    # D-4
    OrgProfileView,
    TenantTypeView,
    InternalTenantTypeView,
    # D-1
    GroupViewSet,
    GroupMemberViewSet,
    # D-2
    InviteCreateView,
    InviteDetailView,
    InviteAcceptView,
    # D-3: tenant-centric (existing)
    TenantGroupAccessView,
    AccountGroupAccessView,
    # D-3: group-centric (onboarding-D3)
    GroupTenantAssignView,
    GroupTenantDeleteView,
    GroupAccountAssignView,
    GroupAccountDeleteView,
)

router = DefaultRouter()
router.register(r"tenants", TenantViewSet, basename="tenant")
router.register(r"groups", GroupViewSet, basename="group")

urlpatterns = [
    # Explicit paths must come BEFORE the router include — the DRF router
    # registers tenants/<pk>/ which would otherwise swallow "idp-by-domain"
    # as a pk lookup and return 404.
    path("tenants/<str:tenant_id>/resync/", ResyncTenantView.as_view(), name="tenant_resync"),
    path("tenants/idp-by-domain/", TenantIDPByDomainView.as_view(), name="idp_by_domain"),
    path("tenants/idp/", TenantIDPConfigListCreateView.as_view(), name="idp_config_list_create"),
    path("tenants/idp/<str:pk>/", TenantIDPConfigDetailView.as_view(), name="idp_config_detail"),
    path("tenants/idp/<str:pk>/activate/", TenantIDPConfigActivateView.as_view(), name="idp_config_activate"),

    # D-4: Org profile + tenant type
    path("org/profile/", OrgProfileView.as_view(), name="org_profile"),
    path("tenants/<str:tenant_id>/type/", TenantTypeView.as_view(), name="tenant_type"),

    # D-1: Group members (nested)
    path("groups/<str:group_pk>/members/", GroupMemberViewSet.as_view({"get": "list", "post": "create"}), name="group_members_list"),
    path("groups/<str:group_pk>/members/<str:pk>/", GroupMemberViewSet.as_view({"delete": "destroy"}), name="group_member_detail"),

    # D-2: Invites
    path("invites/", InviteCreateView.as_view(), name="invite_create"),
    path("invites/<str:token>/", InviteDetailView.as_view(), name="invite_detail"),
    path("invites/<str:token>/accept/", InviteAcceptView.as_view(), name="invite_accept"),

    # D-3: Tenant-centric group access assignment (existing)
    path("tenants/<str:tenant_id>/group-access/", TenantGroupAccessView.as_view(), name="tenant_group_access"),
    path("tenants/<str:tenant_id>/group-access/<str:access_id>/", TenantGroupAccessView.as_view(), name="tenant_group_access_detail"),
    path("tenants/<str:tenant_id>/accounts/<str:account_id>/group-access/", AccountGroupAccessView.as_view(), name="account_group_access"),
    path("tenants/<str:tenant_id>/accounts/<str:account_id>/group-access/<str:access_id>/", AccountGroupAccessView.as_view(), name="account_group_access_detail"),

    # D-3: Group-centric access assignment (onboarding-D3 — AC1..AC4)
    # POST/GET  /api/groups/{group_id}/tenants/
    # DELETE    /api/groups/{group_id}/tenants/{tenant_id}/
    # POST/GET  /api/groups/{group_id}/accounts/
    # DELETE    /api/groups/{group_id}/accounts/{account_id}/
    path("groups/<str:group_id>/tenants/", GroupTenantAssignView.as_view(), name="group_tenant_assign"),
    path("groups/<str:group_id>/tenants/<str:tenant_id>/", GroupTenantDeleteView.as_view(), name="group_tenant_delete"),
    path("groups/<str:group_id>/accounts/", GroupAccountAssignView.as_view(), name="group_account_assign"),
    path("groups/<str:group_id>/accounts/<str:account_id>/", GroupAccountDeleteView.as_view(), name="group_account_delete"),

    # Router last
    path("", include(router.urls)),
]
