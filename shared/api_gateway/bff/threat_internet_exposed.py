"""BFF view: /threats/internet-exposed page.

Retrieves internet-exposed resources from the threat graph engine and
returns them grouped by category with severity KPIs.
"""

from typing import Dict, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import _safe_lower

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/threats/internet-exposed")
async def view_threat_internet_exposed(
    tenant_id: str = Query(...),
):
    """BFF view for the internet-exposed resources page.

    Calls the threat engine's internet-exposed graph endpoint and
    returns KPIs (total, critical, high, medium) and resources grouped
    by resource category.
    """

    results = await fetch_many([
        ("threat", "/api/v1/graph/internet-exposed", {"tenant_id": tenant_id}),
    ])

    exposed_data = results[0]

    # Safely handle None
    if not isinstance(exposed_data, (dict, list)):
        exposed_data = {}

    # Extract resources list — engine returns "exposed_resources" key
    if isinstance(exposed_data, list):
        raw_resources = exposed_data
    else:
        raw_resources = (
            safe_get(exposed_data, "exposed_resources", [])
            or safe_get(exposed_data, "resources", [])
            or safe_get(exposed_data, "exposed", [])
            or safe_get(exposed_data, "data", [])
        )
    if not isinstance(raw_resources, list):
        raw_resources = []

    # Compute severity KPIs — engine returns threat_severities list per resource
    total = len(raw_resources)
    critical = 0
    high = 0
    medium = 0
    for r in raw_resources:
        # Try direct severity field first, then max of threat_severities list
        sev = _safe_lower(r.get("severity") or r.get("risk_level"))
        if not sev:
            severities = r.get("threat_severities", [])
            if isinstance(severities, list) and severities:
                severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                sev = max(severities, key=lambda s: severity_order.get(_safe_lower(s), 0))
                sev = _safe_lower(sev)
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1

    # Group by category (resource_type or service)
    by_category: Dict[str, List[dict]] = {}
    for r in raw_resources:
        cat = (
            r.get("category")
            or r.get("resource_type")
            or r.get("service")
            or "Other"
        )
        by_category.setdefault(cat, []).append(r)

    exposed_grouped: List[dict] = []
    for cat, resources in sorted(by_category.items(), key=lambda x: -len(x[1])):
        exposed_grouped.append({
            "category": cat,
            "count": len(resources),
            "resources": resources,
        })

    return {
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
        },
        "exposedResources": exposed_grouped,
    }
