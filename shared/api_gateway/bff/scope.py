"""BFF view: /scope — global context bar data.

Returns tenant, CSP, account, region, and scan metadata
from the onboarding engine for the scope selector that
appears at the top of every page.
"""

from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/scope")
async def view_scope(
    tenant_id: Optional[str] = Query(None),
):
    """Global scope context for the top-of-page selector bar."""
    results = await fetch_many([
        ("onboarding", "/api/v1/cloud-accounts", {"tenant_id": tenant_id} if tenant_id else {}),
    ])

    accounts_raw = results[0] or []
    if isinstance(accounts_raw, dict):
        accounts_raw = accounts_raw.get("accounts", [])

    # Build unique tenants, providers, accounts, regions
    tenants: Dict[str, Dict] = {}
    providers: set = set()
    accounts: List[Dict] = []
    regions: set = set()

    for a in accounts_raw:
        tid = a.get("tenant_id", "")
        if tid and tid not in tenants:
            tenants[tid] = {
                "id": tid,
                "name": a.get("tenant_name") or tid,
            }
        providers.add((a.get("provider") or "aws").lower())
        accounts.append({
            "id": a.get("account_id") or a.get("account_number", ""),
            "name": a.get("account_name", ""),
            "provider": (a.get("provider") or "aws").lower(),
            "status": a.get("account_status", ""),
            "credential_type": a.get("credential_type", ""),
            "tenant_id": tid,
        })
        # Extract regions from schedule
        sched_regions = a.get("schedule_include_regions") or []
        for r in sched_regions:
            if r:
                regions.add(r)

    return {
        "tenants": list(tenants.values()),
        "providers": sorted(providers),
        "accounts": accounts,
        "regions": sorted(regions),
    }
