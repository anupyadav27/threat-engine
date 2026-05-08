"""
Billing Engine — Pydantic request/response models.

All models use Pydantic v2 semantics.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Plan models
# ---------------------------------------------------------------------------


class PlanResponse(BaseModel):
    """A single subscription plan row."""

    plan_id: UUID
    plan_name: str
    display_name: str
    price_monthly: float
    price_annual: Optional[float] = None
    stripe_price_id: Optional[str] = None
    max_accounts: int
    max_users: int
    scan_freq_per_day: int
    data_retention_days: int
    engine_allowlist: List[str]
    sort_order: int
    is_active: bool = True
    is_public: bool = True


class PlansListResponse(BaseModel):
    """Response for GET /plans."""

    plans: List[Dict[str, Any]]


class CreatePlanRequest(BaseModel):
    """Body for POST /plans (platform:admin only)."""

    plan_name: str = Field(..., description="Unique slug, e.g. 'enterprise_plus'")
    display_name: str
    price_monthly: float = 0.0
    price_annual: Optional[float] = None
    max_accounts: int = 1
    max_users: int = 3
    scan_freq_per_day: int = 0
    data_retention_days: int = 7
    engine_allowlist: Optional[List[str]] = None
    sort_order: int = 99
    is_public: bool = True


class UpdatePlanRequest(BaseModel):
    """Body for PATCH /plans/{plan_id} (platform:admin only).

    All fields are optional — only provided fields are updated.
    """

    display_name: Optional[str] = None
    price_monthly: Optional[float] = None
    price_annual: Optional[float] = None
    max_accounts: Optional[int] = None
    max_users: Optional[int] = None
    scan_freq_per_day: Optional[int] = None
    data_retention_days: Optional[int] = None
    engine_allowlist: Optional[List[str]] = None
    sort_order: Optional[int] = None
    is_public: Optional[bool] = None
    is_active: Optional[bool] = None


# ---------------------------------------------------------------------------
# Subscription models
# ---------------------------------------------------------------------------


class SubscriptionResponse(BaseModel):
    """Response for GET /subscription."""

    subscription_id: UUID
    org_id: str
    plan_id: UUID
    plan: Dict[str, Any]
    status: str
    trial_start_at: Optional[datetime] = None
    trial_end_at: Optional[datetime] = None
    trial_days_remaining: int = 0
    accounts_connected: int
    max_accounts: int
    cancel_at_period_end: bool
    created_at: datetime
    updated_at: datetime


class CancelRequest(BaseModel):
    """Body for POST /cancel."""

    org_id: str
    reason: Optional[str] = None


class ReactivateRequest(BaseModel):
    """Body for POST /reactivate."""

    org_id: str


# ---------------------------------------------------------------------------
# Trial models
# ---------------------------------------------------------------------------


class TrialProvisionRequest(BaseModel):
    """Body for POST /trial/provision."""

    org_id: str
    email_domain: Optional[str] = ""
    admin_email: Optional[str] = None  # Added BILL-08: used for admin_email_domain dedup


class TrialProvisionResponse(BaseModel):
    """Response for POST /trial/provision."""

    provisioned: bool
    reason: Optional[str] = None
    status: str


# ---------------------------------------------------------------------------
# Usage models
# ---------------------------------------------------------------------------


class ConsumeScanTokenRequest(BaseModel):
    """Body for POST /usage/consume-scan-token."""

    org_id: str


class ScanFrequencyCheckResponse(BaseModel):
    """Response for GET /usage/check-scan-frequency."""

    allowed: bool
    tokens_remaining: int
    reset_at: Optional[str] = None


class AccountLimitCheckResponse(BaseModel):
    """Response for GET /usage/check-account-limit."""

    allowed: bool
    accounts_connected: int
    limit: int
    current_tier: str
    upgrade_url: str
