from django.urls import path, include
from config.health import health_check, readiness_check
from user_auth.views.local_auth import UserListView
from user_auth.views.invite_send import InviteUserView, InviteUserAcceptView
from tenant_management.views import InternalTenantTypeView

urlpatterns = [
    path('health', health_check, name='health'),
    path('ready', readiness_check, name='readiness'),
    path('api/auth/', include("user_auth.urls")),
    path('api/', include("tenant_management.urls")),
    path('api/users/', UserListView.as_view(), name='user_list'),

    # onboarding-D2: canonical top-level invite endpoints (AC1 / AC8)
    # accept/ MUST come before invite/ so Django matches the longer prefix first.
    # POST /api/users/invite/accept  — public, token-based user activation
    # POST /api/users/invite         — authenticated (users:write), sends invite
    path('api/users/invite/accept/', InviteUserAcceptView.as_view(), name='users_invite_accept_top'),
    path('api/users/invite/', InviteUserView.as_view(), name='users_invite_top'),

    # D-4: Internal endpoint — no cookie auth; X-Internal-Secret required (AC7)
    path('internal/tenants/<str:tenant_id>/type', InternalTenantTypeView.as_view(), name='internal_tenant_type'),
]
