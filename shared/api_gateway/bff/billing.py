"""BFF view: /billing page.

Aggregates: current subscription, usage metrics, available plans, recent invoices.
Permission: billing:read required; returns 403 for viewer/analyst.

Engine: engine-billing (port 8040)
"""

import asyncio
import logging
import os
from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id_optional
from ._shared import fetch_many, safe_get

logger = logging.getLogger("api-gateway.bff.billing")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

_BILLING_URL = os.getenv("BILLING_ENGINE_URL", "http://engine-billing:8040")


def _billing_url(path: str) -> str:
    """Build a full URL against the billing engine base URL."""
    return f"{_BILLING_URL}{path}"


@router.get("/billing")
async def view_billing(
    request: Request,
    org_id: Optional[str] = Query(None),
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

    # org_id falls back to tenant_id for backward compat
    oid = org_id or tenant_id or ""

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
    usage = usage_data

    # Plans come back as { "plans": [...] } or just [...]
    plans = plans_data.get("plans", plans_data) if isinstance(plans_data, dict) else []
    if not isinstance(plans, list):
        plans = []

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

    return {
        "subscription":     subscription,
        "usage":            usage,
        "plans":            plans,
        "invoices":         invoices,
        "tier":             tier,
        "engine_allowlist": engine_allowlist,
    }
