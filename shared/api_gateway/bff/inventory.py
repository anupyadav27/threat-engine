"""BFF view: /inventory page.

Consolidates into 3 parallel calls (inventory/ui-data + threat/ui-data + onboarding/ui-data).
Adds resilience: cross-engine enrichment with threat data for findings counts,
provider enrichment from cloud_accounts, and fallback when inventory engine is sparse.
"""

import datetime
from typing import Optional, Dict

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_asset, apply_global_filters, _safe_upper

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/inventory")
async def view_inventory(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_run_id: str = Query("latest"),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """Asset list + summary for the inventory page."""

    # ── 3 parallel calls instead of 4 ────────────────────────────────────
    results = await fetch_many([
        ("inventory",  "/api/v1/inventory/ui-data",  {"tenant_id": tenant_id, "scan_run_id": scan_run_id, "limit": str(limit), "offset": str(offset)}),
        ("threat",     "/api/v1/threat/ui-data",     {"tenant_id": tenant_id, "scan_run_id": "latest", "limit": "0"}),
        ("onboarding", "/api/v1/onboarding/ui-data", {"tenant_id": tenant_id}),
    ])

    inventory_data, threat_data, onboarding_data = results

    # Safely unwrap responses
    inventory_data = inventory_data if isinstance(inventory_data, dict) else {}
    threat_data = threat_data if isinstance(threat_data, dict) else {}
    onboarding_data = onboarding_data if isinstance(onboarding_data, dict) else {}

    # ── Extract inventory fields ─────────────────────────────────────────
    summary_resp = inventory_data.get("summary", {})
    if not isinstance(summary_resp, dict):
        summary_resp = {}

    # Normalize assets
    raw_assets = inventory_data.get("assets", [])
    if not isinstance(raw_assets, list):
        raw_assets = []
    assets = [normalize_asset(a) for a in raw_assets]

    # ── Build account->provider mapping from onboarding ──────────────────
    raw_accounts = onboarding_data.get("accounts", [])
    if not isinstance(raw_accounts, list):
        raw_accounts = []
    account_provider_map: Dict[str, str] = {}
    default_provider = ""
    for a in raw_accounts:
        acct_id = a.get("account_id", "")
        prov = (a.get("provider") or a.get("csp") or "").lower()
        if acct_id and prov:
            account_provider_map[acct_id] = prov
            if not default_provider:
                default_provider = prov

    # Enrich assets with provider when missing
    for asset in assets:
        if not asset.get("provider"):
            acct = asset.get("account_id", "")
            asset["provider"] = account_provider_map.get(acct, default_provider)

    # Apply scope filters
    filtered = apply_global_filters(assets, provider, account, region)

    # ── KPI derivation ───────────────────────────────────────────────────
    total = len(filtered)
    now = datetime.datetime.utcnow()
    week_ago = now - datetime.timedelta(days=7)
    new_this_week = sum(1 for a in filtered if a.get("created_at") and str(a["created_at"]) > week_ago.isoformat())
    unmanaged = sum(1 for a in filtered if not a.get("tags") or len(a.get("tags", {})) == 0)
    exposed = sum(1 for a in filtered if a.get("internet_exposed") or a.get("public"))
    critical = sum(1 for a in filtered if (
        (isinstance(a.get("findings"), dict) and a["findings"].get("critical", 0) > 0)
        or a.get("severity") == "critical"
    ))
    drift_count = summary_resp.get("total_drift", 0)

    # Enrich with threat data when inventory is sparse
    threat_summary = threat_data.get("summary", {})
    if isinstance(threat_summary, dict):
        by_sev = threat_summary.get("by_severity", {}) or threat_summary.get("threats_by_severity", {})
    else:
        by_sev = {}
    if not critical and isinstance(by_sev, dict):
        critical = by_sev.get("critical", 0)

    # ── Provider breakdown ───────────────────────────────────────────────
    by_provider: Dict[str, int] = {}
    for a in filtered:
        p = (a.get("provider") or "unknown").upper()
        by_provider[p] = by_provider.get(p, 0) + 1

    # If no assets from inventory, derive from cloud accounts
    if not by_provider:
        for a in raw_accounts:
            prov = _safe_upper(a.get("provider") or a.get("csp"))
            resources = a.get("total_resources", 0) or 0
            if prov:
                by_provider[prov] = by_provider.get(prov, 0) + resources
        total = sum(by_provider.values())

    # Also try summary-level by_provider if available and more complete
    if not by_provider:
        summary_by_provider = summary_resp.get("assets_by_provider", {})
        if isinstance(summary_by_provider, dict) and summary_by_provider:
            for prov_key, count in summary_by_provider.items():
                by_provider[prov_key.upper()] = count if isinstance(count, int) else 0
            if not total:
                total = sum(by_provider.values())

    # ── Service breakdown ────────────────────────────────────────────────
    by_service: Dict[str, int] = {}
    for a in filtered:
        svc = a.get("service") or a.get("resource_type", "other")
        by_service[svc] = by_service.get(svc, 0) + 1

    # Fall back to summary-level by_service if asset-level is empty
    if not by_service:
        summary_by_service = summary_resp.get("assets_by_service", {})
        if isinstance(summary_by_service, dict):
            by_service = {k: v for k, v in summary_by_service.items() if isinstance(v, int)}

    return {
        "kpi": {
            "totalAssets": total or summary_resp.get("total_assets", 0),
            "newThisWeek": new_this_week,
            "unmanagedAssets": unmanaged,
            "exposedAssets": exposed,
            "criticalFindings": critical,
            "driftCount": drift_count,
        },
        "assets": filtered,
        "total": inventory_data.get("total", len(filtered)),
        "has_more": inventory_data.get("has_more", False),
        "summary": summary_resp,
        "byProvider": by_provider,
        "byService": dict(sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:15]),
    }
