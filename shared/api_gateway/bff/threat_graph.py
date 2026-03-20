"""BFF view: /threats/graph page.

Retrieves the resource relationship graph from the inventory engine
and returns nodes + links in a UI-ready format for graph visualization.
"""

from typing import Optional, Dict, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/threats/graph")
async def view_threat_graph(
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
):
    """BFF view for the threat graph visualization page.

    Calls the inventory engine's graph endpoint and returns KPIs
    (node count, edge count, average risk) plus nodes and links
    arrays for the graph renderer.
    """

    results = await fetch_many([
        ("inventory", "/api/v1/inventory/runs/latest/graph", {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
        }),
    ])

    graph_data = results[0]

    # Safely handle None
    if not isinstance(graph_data, dict):
        graph_data = {}

    nodes: List[dict] = safe_get(graph_data, "nodes", []) or []
    if not isinstance(nodes, list):
        nodes = []

    edges: List[dict] = (
        safe_get(graph_data, "edges", [])
        or safe_get(graph_data, "links", [])
        or []
    )
    if not isinstance(edges, list):
        edges = []

    # Compute KPIs
    total_nodes = len(nodes)
    total_edges = len(edges)
    risk_scores = [
        n.get("risk_score") or n.get("riskScore", 0)
        for n in nodes
        if (n.get("risk_score") or n.get("riskScore", 0)) > 0
    ]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    return {
        "kpi": {
            "nodes": total_nodes,
            "edges": total_edges,
            "avgRisk": avg_risk,
        },
        "nodes": nodes,
        "links": edges,
    }
