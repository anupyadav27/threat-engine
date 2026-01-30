"""
URLs for admin analytics app.
"""
from django.urls import path
from . import views

urlpatterns = [
    path('overview', views.AnalyticsOverviewView.as_view(), name='analytics-overview'),
    path('compliance', views.ComplianceAnalyticsView.as_view(), name='analytics-compliance'),
    path('scans', views.ScanAnalyticsView.as_view(), name='analytics-scans'),
    path('trends', views.TrendsView.as_view(), name='analytics-trends'),
    path('tenants/comparison', views.TenantComparisonView.as_view(), name='analytics-tenant-comparison'),
]
