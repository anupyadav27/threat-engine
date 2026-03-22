"""BFF view: /threats/blast-radius page.

PostgreSQL-based — reads from threat_analysis.analysis_results JSONB.
Shows per-detection blast radius data (reachable resources, depth distribution).
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# Known AWS region prefixes — anything else is likely a service name stored by mistake
_REGION_PREFIXES = ("us-", "eu-", "ap-", "ca-", "sa-", "me-", "af-", "il-", "global")


def _fix_region(region: str, resource_uid: str) -> str:
    """Extract actual region from ARN when DB stores the service name instead."""
    if region and any(region.startswith(p) for p in _REGION_PREFIXES):
        return region
    # Try to extract from ARN: arn:aws:SERVICE:REGION:ACCOUNT:...
    parts = resource_uid.split(":") if resource_uid else []
    if len(parts) >= 4 and parts[3]:
        return parts[3]
    return region or "global"


@router.get("/threats/blast-radius")
async def view_threat_blast_radius(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    resource_uid: Optional[str] = Query(None),
):
    """BFF view for blast radius page — Orca-style.

    Fetches aggregated blast radius data from PostgreSQL (threat_analysis JSONB).
    Optionally filters to a specific resource_uid.
    """

    params = {"tenant_id": tenant_id, "limit": "500"}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id

    results = await fetch_many([
        ("threat", "/api/v1/threat/analysis/blast-radius", params),
    ])

    raw = results[0]
    if not isinstance(raw, dict):
        raw = {}

    items = safe_get(raw, "items", [])
    if not isinstance(items, list):
        items = []

    summary = safe_get(raw, "summary", {})

    # Filter by resource_uid if requested
    if resource_uid:
        items = [i for i in items if i.get("resource_uid") == resource_uid]

    # KPI (computed before filtering out zero-reachable)
    all_count = len(items)
    total_reachable = sum(i.get("reachable_count", 0) for i in items)
    internet_count = sum(1 for i in items if i.get("is_internet_reachable"))
    with_blast = sum(1 for i in items if i.get("reachable_count", 0) > 0)

    kpi = {
        "totalDetections": safe_get(summary, "total_detections", all_count),
        "detectionsWithBlast": safe_get(summary, "detections_with_blast", with_blast),
        "totalReachable": safe_get(summary, "total_reachable_resources", total_reachable),
        "internetExposed": internet_count,
    }

    # Normalize items for UI — show ALL detections (including zero connectivity)
    blast_items = []
    for item in items:
        resource_name = item.get("resource_uid", "")
        # Extract short name from ARN
        if "/" in resource_name:
            resource_name = resource_name.split("/")[-1]
        elif ":" in resource_name:
            resource_name = resource_name.split(":")[-1]

        # Compute max hops from depth_distribution or path_edges
        depth_dist = item.get("depth_distribution", {})
        path_edges = item.get("path_edges", [])
        max_hops = max((int(k) for k in depth_dist.keys()), default=0) if depth_dist else 0
        if not max_hops and path_edges:
            max_hops = max((e.get("hop", 0) for e in path_edges), default=0)

        blast_items.append({
            "detectionId": item.get("detection_id", ""),
            "resourceUid": item.get("resource_uid", ""),
            "resourceName": resource_name,
            "resourceType": item.get("resource_type", ""),
            "provider": (item.get("provider") or "").upper() or "--",
            "accountId": item.get("account_id", ""),
            "region": _fix_region(item.get("region", ""), item.get("resource_uid", "")),
            "severity": item.get("severity", ""),
            "riskScore": item.get("risk_score", 0),
            "verdict": item.get("verdict", ""),
            "reachableCount": item.get("reachable_count", 0),
            "maxHops": max_hops,
            "reachableResources": item.get("reachable_resources", []),
            "pathEdges": item.get("path_edges", []),
            "isInternetReachable": item.get("is_internet_reachable", False),
            "ruleName": item.get("rule_name", ""),
        })

    return {
        "kpi": kpi,
        "blastItems": blast_items,
    }
