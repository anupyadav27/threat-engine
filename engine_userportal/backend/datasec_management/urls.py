"""
URLs for DataSec Management
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import DataSecViewSet

router = DefaultRouter()
router.register(r'', DataSecViewSet, basename='datasec')

urlpatterns = router.urls
