"""
URLs for Inventory Management
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import InventoryAssetViewSet

router = DefaultRouter()
router.register(r'assets', InventoryAssetViewSet, basename='inventory-asset')

urlpatterns = [
    path('', include(router.urls)),
]
