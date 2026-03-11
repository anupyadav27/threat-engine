"""
BFF Views Layer for API Gateway

Provides pre-aggregated, UI-ready endpoints that merge data from multiple engines
into the exact shapes the frontend expects.  Each view endpoint gathers data from
one or more backend engines via async HTTP calls and returns a single response.

Mounted at:  /gateway/api/v1/views/...

=== VIEWS ===
  GET /gateway/api/v1/views/inventory
      → Calls inventory engine for assets + scan summary
      → Returns UI-ready inventory page payload

  GET /gateway/api/v1/views/inventory/summary
      → Lightweight summary-only (KPIs for top cards)
===
"""

from __future__ import annotations

import os
import logging
from typing import Optional, List

import httpx
from fastapi import APIRouter, Query, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gateway/api/v1/views", tags=["views"])

# Engine base URLs (same env vars used by SERVICE_ROUTES in main.py)
INVENTORY_URL = os.getenv("INVENTORY_ENGINE_URL", "http://engine-inventory:8022")
CHECK_URL = os.getenv("CHECK_ENGINE_URL", "http://engine-check:8002")

_HTTP_TIMEOUT = 15.0


async def _fetch_json(url: str, params: dict) -> dict:
    """Best-effort GET — returns empty dict on failure."""
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning(f"BFF fetch failed: {url} — {exc}")
        return {}


@router.get("/inventory")
async def view_inventory(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    account_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """
    Aggregated inventory view for the UI list page.

    Merges:
      1. Asset list from inventory engine (with UI-ready field names)
      2. Scan summary from inventory engine (KPIs)
      3. Drift summary from inventory engine

    Returns a single payload the frontend can consume without further joins.
    """
    # Build common params
    params = {"tenant_id": tenant_id, "limit": limit, "offset": offset}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id
    if provider:
        params["provider"] = provider
    if region:
        params["region"] = region
    if resource_type:
        params["resource_type"] = resource_type
    if account_id:
        params["account_id"] = account_id

    # 1. Fetch assets
    assets_data = await _fetch_json(
        f"{INVENTORY_URL}/api/v1/inventory/assets",
        params,
    )

    assets = assets_data.get("assets", [])
    total = assets_data.get("total", len(assets))

    # 2. Fetch scan summary (for KPIs)
    summary_params = {"tenant_id": tenant_id}
    if scan_run_id:
        summary_params["scan_run_id"] = scan_run_id
    summary_data = await _fetch_json(
        f"{INVENTORY_URL}/api/v1/inventory/runs/latest/summary",
        summary_params,
    )

    # 3. Fetch drift summary (lightweight)
    drift_data = await _fetch_json(
        f"{INVENTORY_URL}/api/v1/inventory/drift",
        {"tenant_id": tenant_id, "scan_run_id": scan_run_id or "latest"},
    )

    # --- Compute derived KPIs ---
    providers_set = set()
    unmanaged_count = 0
    exposed_count = 0
    for a in assets:
        providers_set.add(a.get("provider", ""))
        tags = a.get("tags")
        if not tags or (isinstance(tags, dict) and len(tags) == 0):
            unmanaged_count += 1
        if (a.get("risk_score") or 0) >= 70:
            exposed_count += 1

    return {
        "assets": assets,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + len(assets)) < total,
        "summary": {
            "total_assets": summary_data.get("total_assets", total),
            "total_relationships": summary_data.get("total_relationships", 0),
            "total_drift": drift_data.get("summary", {}).get("total_drift", 0),
            "providers_scanned": summary_data.get("providers_scanned") or list(providers_set),
            "unmanaged_assets": unmanaged_count,
            "exposed_assets": exposed_count,
            "multi_cloud_count": len(providers_set),
            "assets_by_provider": summary_data.get("assets_by_provider", {}),
            "assets_by_resource_type": summary_data.get("assets_by_resource_type", {}),
            "assets_by_region": summary_data.get("assets_by_region", {}),
        },
    }


@router.get("/inventory/summary")
async def view_inventory_summary(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
):
    """Lightweight inventory summary — only KPIs, no asset list."""
    summary_params = {"tenant_id": tenant_id}
    if scan_run_id:
        summary_params["scan_run_id"] = scan_run_id

    summary_data = await _fetch_json(
        f"{INVENTORY_URL}/api/v1/inventory/runs/latest/summary",
        summary_params,
    )

    drift_data = await _fetch_json(
        f"{INVENTORY_URL}/api/v1/inventory/drift",
        {"tenant_id": tenant_id, "scan_run_id": scan_run_id or "latest"},
    )

    return {
        "total_assets": summary_data.get("total_assets", 0),
        "total_relationships": summary_data.get("total_relationships", 0),
        "total_drift": drift_data.get("summary", {}).get("total_drift", 0),
        "providers_scanned": summary_data.get("providers_scanned", []),
        "assets_by_provider": summary_data.get("assets_by_provider", {}),
        "assets_by_resource_type": summary_data.get("assets_by_resource_type", {}),
        "assets_by_region": summary_data.get("assets_by_region", {}),
    }
