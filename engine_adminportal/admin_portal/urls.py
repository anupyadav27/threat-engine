"""
URL configuration for admin_portal project.
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.admin_monitoring import views as monitoring_views
from apps.admin_analytics import views as analytics_views
from apps.admin_management import views as management_views
from apps.admin_audit import views as audit_views
from apps.engine_integration import views as health_views

router = DefaultRouter()
router.register(r'tenants', monitoring_views.TenantViewSet, basename='tenant')
router.register(r'tenants-management', management_views.TenantManagementViewSet, basename='tenant-management')
router.register(r'users', management_views.UserViewSet, basename='user')
router.register(r'audit/logs', audit_views.AuditLogViewSet, basename='audit-log')
router.register(r'audit/alerts', audit_views.AlertViewSet, basename='alert')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/admin/', include(router.urls)),
    path('api/admin/analytics/', include('apps.admin_analytics.urls')),
    path('api/admin/health/', include('apps.engine_integration.urls')),
    path('api/admin/dashboard/', monitoring_views.DashboardOverviewView.as_view(), name='dashboard-overview'),
    path('health/', health_views.HealthCheckView.as_view(), name='health-check'),
]
