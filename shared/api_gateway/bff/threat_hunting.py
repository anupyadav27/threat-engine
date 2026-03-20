"""BFF view: /threats/hunting page.

Consolidates threat intelligence indicators (IOCs) and hunt queries
into a single UI-ready response for the threat hunting page.
"""

from typing import List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import normalize_intel

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/threats/hunting")
async def view_threat_hunting(
    tenant_id: str = Query(...),
):
    """BFF view for the threat hunting page.

    Fans out to the intel and hunt query endpoints in parallel and
    returns KPIs, IOC indicators, and saved hunt queries.
    """

    results = await fetch_many([
        ("threat", "/api/v1/intel", {"tenant_id": tenant_id}),
        ("threat", "/api/v1/hunt/queries", {"tenant_id": tenant_id}),
    ])

    intel_data, hunt_data = results

    # Safely handle None
    if not isinstance(intel_data, (dict, list)):
        intel_data = {}
    if not isinstance(hunt_data, (dict, list)):
        hunt_data = {}

    # IOCs
    if isinstance(intel_data, list):
        raw_iocs = intel_data
    else:
        raw_iocs = (
            safe_get(intel_data, "indicators", [])
            or safe_get(intel_data, "intel", [])
            or safe_get(intel_data, "data", [])
        )
    if not isinstance(raw_iocs, list):
        raw_iocs = []
    iocs = [normalize_intel(i) for i in raw_iocs]

    # Hunt queries
    if isinstance(hunt_data, list):
        raw_queries = hunt_data
    else:
        raw_queries = (
            safe_get(hunt_data, "queries", [])
            or safe_get(hunt_data, "hunt_queries", [])
            or safe_get(hunt_data, "data", [])
        )
    if not isinstance(raw_queries, list):
        raw_queries = []

    hunt_queries: List[dict] = []
    for q in raw_queries:
        hunt_queries.append({
            "id": q.get("id") or q.get("query_id", ""),
            "name": q.get("name") or q.get("query_name", ""),
            "description": q.get("description", ""),
            "query": q.get("query") or q.get("expression", ""),
            "severity": (q.get("severity") or "medium").lower(),
            "lastRun": q.get("last_run") or q.get("last_executed"),
            "resultCount": q.get("result_count") or q.get("results", 0),
            "status": q.get("status", "active"),
        })

    # KPIs
    total_iocs = len(iocs)
    total_queries = len(hunt_queries)
    active_queries = sum(1 for q in hunt_queries if q.get("status") == "active")
    high_relevance = sum(1 for i in iocs if (i.get("relevance") or 0) >= 70)

    return {
        "kpi": {
            "totalIocs": total_iocs,
            "highRelevance": high_relevance,
            "totalQueries": total_queries,
            "activeQueries": active_queries,
        },
        "iocs": iocs,
        "huntQueries": hunt_queries,
    }
