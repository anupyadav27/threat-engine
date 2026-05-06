"""Shared lenient response models for billing engine (STORY-ENG-PYDANTIC-COVERAGE)."""

from typing import Optional

from pydantic import BaseModel


class _BillingBase(BaseModel):
    """Lenient base — passes engine-native fields through."""

    model_config = {"extra": "allow"}


class HealthResponse(BaseModel):
    status: str
    db: Optional[str] = None
    stripe: Optional[str] = None


class BillingLenientResponse(_BillingBase):
    """Catch-all for billing endpoints whose shape varies by org/plan."""
