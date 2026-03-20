"""BFF view: /threats/blast-radius page.

Shows graph summary, internet-exposed resources, and optionally the blast
radius for a specific resource when resource_uid is provided.
"""

from typing import Optional, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/threats/blast-radius")
async def view_threat_blast_radius(
    tenant_id: str = Query(...),
    resource_uid: Optional[str] = Query(None),
):
    """BFF view for blast radius page.

    Always fetches graph summary and internet-exposed resources.
    If resource_uid is provided, also fetches the blast radius for
    that specific resource.
    """

    calls = [
        ("threat", "/api/v1/graph/summary", {"tenant_id": tenant_id}),
        ("threat", "/api/v1/graph/internet-exposed", {"tenant_id": tenant_id}),
    ]
    if resource_uid:
        calls.append(
            ("threat", f"/api/v1/graph/blast-radius/{resource_uid}", {"tenant_id": tenant_id})
        )

    results = await fetch_many(calls)

    summary_data = results[0]
    exposed_data = results[1]
    blast_data = results[2] if resource_uid else None

    # Safely handle None
    if not isinstance(summary_data, dict):
        summary_data = {}
    if not isinstance(exposed_data, (dict, list)):
        exposed_data = {}
    if blast_data is not None and not isinstance(blast_data, dict):
        blast_data = {}

    # KPI from summary — engine returns node_counts/relationship_counts dicts
    node_counts = safe_get(summary_data, "node_counts", {})
    rel_counts = safe_get(summary_data, "relationship_counts", {})
    total_nodes = (
        sum(node_counts.values()) if isinstance(node_counts, dict)
        else safe_get(summary_data, "total_nodes", 0)
        or safe_get(summary_data, "nodes", 0)
    )
    total_edges = (
        sum(rel_counts.values()) if isinstance(rel_counts, dict)
        else safe_get(summary_data, "total_edges", 0)
        or safe_get(summary_data, "edges", 0)
    )

    kpi = {
        "totalNodes": total_nodes,
        "totalEdges": total_edges,
        "internetExposed": safe_get(summary_data, "internet_exposed_count", 0),
        "criticalPaths": safe_get(summary_data, "critical_paths", 0),
    }

    # Internet-exposed resources — engine returns "exposed_resources" key
    if isinstance(exposed_data, list):
        exposed_list = exposed_data
    else:
        exposed_list = (
            safe_get(exposed_data, "exposed_resources", [])
            or safe_get(exposed_data, "resources", [])
            or safe_get(exposed_data, "exposed", [])
            or safe_get(exposed_data, "data", [])
        )
    if not isinstance(exposed_list, list):
        exposed_list = []

    # Update internetExposed KPI from actual list if summary didn't provide it
    if not kpi["internetExposed"] and exposed_list:
        kpi["internetExposed"] = len(exposed_list)

    response = {
        "kpi": kpi,
        "internetExposed": exposed_list,
    }

    # Blast radius for the searched resource
    if resource_uid and blast_data:
        response["blastRadius"] = {
            "resourceUid": resource_uid,
            "reachableCount": safe_get(blast_data, "reachable_count", 0) or safe_get(blast_data, "total", 0),
            "criticalCount": safe_get(blast_data, "critical_count", 0),
            "nodes": safe_get(blast_data, "nodes", []),
            "edges": safe_get(blast_data, "edges", []),
            "affectedServices": safe_get(blast_data, "affected_services", []),
        }

    return response
