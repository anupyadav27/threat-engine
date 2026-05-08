"""BFF view: /billing page.

Aggregates: current subscription, usage metrics, available plans, recent invoices.
Permission: billing:read required; returns 403 for viewer/analyst.

Engine: engine-billing (port 8040)
"""

import json as _json
import logging
import os
import time as _time
from datetime import datetime
from datetime import timezone as _tz
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse as _JSONResponse

from ._auth import resolve_tenant_id_optional
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.billing import BillingResponse

logger = logging.getLogger("api-gateway.bff.billing")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ---------------------------------------------------------------------------
# Trial-status endpoint — /api/v1/billing/trial-status
# Separate router (not under /views/) so it is available without a page-view
# prefix and does not require billing:read permission (any authenticated tenant).
# ---------------------------------------------------------------------------

_trial_router = APIRouter(prefix="/api/v1/billing", tags=["Billing"])

# In-process TTL cache: {engine_tenant_id: (monotonic_ts, payload)}
_trial_cache: Dict[str, Tuple[float, Any]] = {}
_TRIAL_CACHE_TTL = 60  # seconds


@_trial_router.get("/trial-status")
async def get_trial_status(request: Request) -> Any:
    """Return trial status for the authenticated tenant.

    Auth: engine_tenant_id from X-Auth-Context only — never from query string.
    Platform users (role_level <= 1): returns {"applicable": false}.
    Unauthenticated: 401.
    Cache: 60 s per engine_tenant_id.

    Returns:
        Dict with applicable, status, trial_end_at, trial_days_remaining, tier.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context")
    if not auth_ctx_header:
        return _JSONResponse(status_code=401, content={"error": "unauthenticated"})

    try:
        auth_ctx = _json.loads(auth_ctx_header)
    except Exception:
        return _JSONResponse(status_code=401, content={"error": "invalid_auth_context"})

    engine_tenant_id: Optional[str] = (
        auth_ctx.get("engine_tenant_id") or auth_ctx.get("tenant_id")
    )
    role_level: int = auth_ctx.get("role_level", 99)

    if not engine_tenant_id:
        return _JSONResponse(status_code=401, content={"error": "no_tenant_id"})

    # Platform-level users (role_level 0 or 1) — billing not applicable
    if isinstance(role_level, int) and role_level <= 1:
        return {"applicable": False}

    # Check in-process cache
    cached = _trial_cache.get(engine_tenant_id)
    if cached:
        ts, payload = cached
        if _time.monotonic() - ts < _TRIAL_CACHE_TTL:
            return payload

    # Call billing engine for subscription data
    import httpx
    from ._shared import ENGINE_URLS, ENGINE_TIMEOUTS, DEFAULT_TIMEOUT

    billing_url = ENGINE_URLS.get("billing", "http://engine-billing:8040")
    path = f"/api/v1/billing/subscription"
    params = {"org_id": engine_tenant_id}
    t = ENGINE_TIMEOUTS.get("billing", DEFAULT_TIMEOUT)
    auth_header = {"X-Auth-Context": auth_ctx_header}

    sub_data: Dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(timeout=t) as client:
            resp = await client.get(
                f"{billing_url}{path}",
                params=params,
                headers=auth_header,
            )
            if resp.status_code == 200:
                sub_data = resp.json()
    except Exception as exc:
        logger.warning("trial-status: billing engine call failed: %s", exc)

    if not isinstance(sub_data, dict):
        sub_data = {}

    # Normalise field name — older billing builds send trial_end instead of trial_end_at
    if "trial_end" in sub_data and "trial_end_at" not in sub_data:
        sub_data["trial_end_at"] = sub_data.pop("trial_end")

    status: str = sub_data.get("status", "unknown")
    trial_end_at: Optional[str] = sub_data.get("trial_end_at")
    trial_days_remaining: Optional[int] = sub_data.get("trial_days_remaining")

    # Compute days remaining if billing engine did not include it
    if status == "trialing" and trial_end_at and trial_days_remaining is None:
        try:
            end_dt = datetime.fromisoformat(trial_end_at.replace("Z", "+00:00"))
            trial_days_remaining = max(0, (end_dt - datetime.now(_tz.utc)).days)
        except Exception:
            trial_days_remaining = None

    payload = {
        "applicable": True,
        "status": status,
        "trial_end_at": trial_end_at,
        "trial_days_remaining": trial_days_remaining,
        "tier": sub_data.get("tier", "unknown"),
    }

    _trial_cache[engine_tenant_id] = (_time.monotonic(), payload)
    return payload

_BILLING_URL = os.getenv("BILLING_ENGINE_URL", "http://engine-billing:8040")


def _billing_url(path: str) -> str:
    """Build a full URL against the billing engine base URL."""
    return f"{_BILLING_URL}{path}"


@router.get("/billing", response_model=BillingResponse, response_model_exclude_none=False)
async def view_billing(
    request: Request,
):
    """Single endpoint returning everything the billing portal page needs.

    Calls the billing engine in parallel for:
    - Current subscription details
    - Usage metrics (accounts, scans)
    - Available plan catalogue
    - Recent invoice history (last 10)

    Requires billing:read permission — the gateway enforces this via X-Auth-Context.
    Returns 403-shaped payload if the engine returns 403.
    """
    tenant_id = resolve_tenant_id_optional(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(
        request.state, "auth_header", None
    )
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("billing")

    oid = tenant_id or ""

    results = await fetch_many(
        [
            ("billing", "/api/v1/billing/subscription", {"org_id": oid}),
            ("billing", "/api/v1/billing/usage",        {"org_id": oid}),
            ("billing", "/api/v1/billing/plans",        {}),
            ("billing", "/api/v1/billing/invoices",     {"org_id": oid, "limit": "10"}),
        ],
        auth_headers=fwd_headers,
    )

    sub_data, usage_data, plans_data, inv_data = results
    meta.record_engine("billing", "/api/v1/billing/subscription", sub_data)
    meta.record_engine("billing", "/api/v1/billing/usage", usage_data)
    meta.record_engine("billing", "/api/v1/billing/plans", plans_data)
    meta.record_engine("billing", "/api/v1/billing/invoices", inv_data)

    # Each is None on engine failure — normalise to empty dict/list
    if not isinstance(sub_data, dict):
        sub_data = {}
    if not isinstance(usage_data, dict):
        usage_data = {}
    if not isinstance(plans_data, dict):
        plans_data = {}
    if not isinstance(inv_data, dict):
        inv_data = {}

    subscription = sub_data

    # Normalise trial date field — billing engine sends trial_end_at;
    # older builds may send trial_end. Standardise to trial_end_at throughout.
    if "trial_end" in subscription and "trial_end_at" not in subscription:
        subscription["trial_end_at"] = subscription.pop("trial_end")

    # Compute trial_days_remaining if not already present
    if subscription.get("status") == "trialing" and subscription.get("trial_end_at"):
        try:
            from datetime import datetime, timezone as _tz
            end_dt = datetime.fromisoformat(
                subscription["trial_end_at"].replace("Z", "+00:00")
            )
            delta = end_dt - datetime.now(_tz.utc)
            subscription.setdefault("trial_days_remaining", max(0, delta.days))
        except Exception:
            pass  # non-fatal; UI can compute from trial_end_at

    usage = usage_data

    # Plans come back as { "plans": [...] } or just [...]
    raw_plans = plans_data.get("plans", plans_data) if isinstance(plans_data, dict) else []
    if not isinstance(raw_plans, list):
        raw_plans = []
    plans = [
        {
            **p,
            "plan_id":       p.get("plan_id") or p.get("id", ""),
            "tier":          p.get("tier") or p.get("name", ""),
            "price_monthly": p.get("price_monthly") or p.get("price", {}).get("monthly", 0),
            "price_annual":  p.get("price_annual") or p.get("price", {}).get("annual", 0),
        }
        for p in raw_plans if isinstance(p, dict)
    ]

    # Invoices come back as { "invoices": [...] } or [...]
    invoices_raw = inv_data.get("invoices", inv_data) if isinstance(inv_data, dict) else []
    if not isinstance(invoices_raw, list):
        invoices_raw = []

    # Normalise invoice rows to a stable shape for the table
    invoices = []
    for inv in invoices_raw:
        if not isinstance(inv, dict):
            continue
        invoices.append(
            {
                "id":                 inv.get("id", ""),
                "date":               inv.get("date") or inv.get("created_at", ""),
                "amount":             inv.get("amount") or inv.get("amount_due", 0),
                "currency":           inv.get("currency", "usd").upper(),
                "status":             inv.get("status", ""),
                "hosted_invoice_url": inv.get("hosted_invoice_url", ""),
                "period_start":       inv.get("period_start", ""),
                "period_end":         inv.get("period_end", ""),
            }
        )

    # Surface the subscription tier and engine_allowlist so the UI can gate nav items
    tier = safe_get(subscription, "tier", "free")
    engine_allowlist = safe_get(subscription, "engine_allowlist", [])

    # Ensure usage has the fields the UI expects
    if isinstance(usage, dict):
        usage.setdefault("scans_today",      0)
        usage.setdefault("scans_this_month", 0)
        usage.setdefault("scans_per_month",  0)
        usage.setdefault("accounts_connected", 0)
        usage.setdefault("max_accounts",     0)
        usage.setdefault("scan_freq_per_day", 0)

    # Banner for trial / overdue status
    banner = None
    if subscription.get("status") == "trialing":
        days = subscription.get("trial_days_remaining")
        banner = {
            "type": "warning",
            "message": f"Trial ends in {days} day{'s' if days != 1 else ''}" if days is not None else "Trial ending soon",
        }
    elif subscription.get("status") == "past_due":
        banner = {"type": "error", "message": "Payment overdue — update your billing information"}

    result = {
        "subscription":     subscription,
        "usage":            usage,
        "plans":            plans,
        "invoices":         invoices,
        "tier":             tier,
        "engine_allowlist": engine_allowlist,
        "banner":           banner,
        # data wrapper so UI `data.subscription` etc. resolves correctly
        "data": {
            "subscription": subscription,
            "usage":        usage,
            "plans":        plans,
            "invoices":     invoices,
        },
        "_meta": meta.to_dict(),
    }
    return result
