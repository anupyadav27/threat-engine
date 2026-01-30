# threats_management/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ThreatViewSet

router = DefaultRouter()
router.register(r"threats", ThreatViewSet, basename="threat")

urlpatterns = [
    path("", include(router.urls)),
]