"""
threat_v1 health routes only.

This engine is now a pipeline-only worker. UI-facing incident/scan-status
endpoints have been removed — all threat visualization goes through
attack-paths. Health probes in main.py take precedence over these stubs.
"""
from __future__ import annotations

from fastapi import APIRouter
from threat_v1.schemas.models import HealthResponse

router = APIRouter()


@router.get("/api/v1/health/live", response_model=HealthResponse, tags=["health"])
def health_live() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/api/v1/health/ready", response_model=HealthResponse, tags=["health"])
def health_ready() -> HealthResponse:
    return HealthResponse(status="ok")
