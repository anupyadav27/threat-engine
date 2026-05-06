"""Shared lenient response models for platform-admin engine (STORY-ENG-PYDANTIC-COVERAGE)."""

from typing import Optional

from pydantic import BaseModel


class _PlatformAdminBase(BaseModel):
    """Lenient base — passes engine-native fields through."""

    model_config = {"extra": "allow"}


class HealthResponse(BaseModel):
    status: str


class PlatformAdminLenientResponse(_PlatformAdminBase):
    """Catch-all for platform-admin endpoints with heterogeneous shapes."""
