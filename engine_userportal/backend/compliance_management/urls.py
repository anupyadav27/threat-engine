"""
URLs for Compliance Management
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ComplianceViewSet

router = DefaultRouter()
router.register(r'', ComplianceViewSet, basename='compliance')

urlpatterns = router.urls
