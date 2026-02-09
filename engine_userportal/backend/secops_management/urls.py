from django.urls import path
from . import views

urlpatterns = [
    path("secops/scans", views.list_scans),
    path("secops/scans/<str:scan_id>", views.get_scan),
    path("secops/scans/<str:scan_id>/findings", views.get_findings),
]
