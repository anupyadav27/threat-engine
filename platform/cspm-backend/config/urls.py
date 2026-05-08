from django.urls import path, include
from config.health import health_check, readiness_check
from user_auth.views.local_auth import UserListView

urlpatterns = [
    path('health', health_check, name='health'),
    path('ready', readiness_check, name='readiness'),
    path('api/auth/', include("user_auth.urls")),
    path('api/', include("tenant_management.urls")),
    path('api/users/', UserListView.as_view(), name='user_list'),
]
