"""
URLs for engine integration (health endpoints).
"""
from django.urls import path
from . import views

urlpatterns = [
    path('engines', views.EngineHealthView.as_view(), name='engine-health'),
    path('database', views.DatabaseHealthView.as_view(), name='database-health'),
    path('services', views.ServicesHealthView.as_view(), name='services-health'),
    path('summary', views.HealthSummaryView.as_view(), name='health-summary'),
]
