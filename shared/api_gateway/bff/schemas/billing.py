"""BFF contract schema — /billing view.

The billing data wrapper is intentional: UI reads data.subscription,
data.plans, data.usage, data.invoices — so the data{} sub-dict is kept.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class BillingSubscription(BaseModel):
    model_config = ConfigDict(extra="allow")

    plan: str = ""
    status: str = ""
    tier: str = ""
    trial_ends_at: Optional[str] = None
    current_period_end: Optional[str] = None


class BillingUsage(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_credits_used: int = 0
    scan_credits_total: int = 0
    assets_scanned: int = 0


class BillingInvoice(BaseModel):
    model_config = ConfigDict(extra="allow")

    invoice_id: str = ""
    amount: float = 0.0
    currency: str = "usd"
    status: str = ""
    created_at: str = ""


class BillingDataWrapper(BaseModel):
    """Inner data{} object that the UI reads as data.subscription etc."""
    model_config = ConfigDict(extra="allow")

    subscription: Optional[Any] = None
    usage: Optional[Any] = None
    plans: List[Any] = Field(default_factory=list)
    invoices: List[Any] = Field(default_factory=list)


class BillingResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    subscription: Optional[Any] = None
    usage: Optional[Any] = None
    plans: List[Any] = Field(default_factory=list)
    invoices: List[Any] = Field(default_factory=list)
    tier: str = ""
    engine_allowlist: List[str] = Field(default_factory=list)
    banner: Optional[Dict[str, Any]] = None
    data: BillingDataWrapper = Field(default_factory=BillingDataWrapper)
    applicable: Optional[bool] = None
    _meta: Optional[Dict[str, Any]] = None
