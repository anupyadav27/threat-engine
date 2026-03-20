"""BFF view: /threats/attack-paths page.

Retrieves attack path graph data from the threat engine and returns
normalized, UI-ready attack paths with KPIs.
"""

import hashlib
from typing import Any, Dict, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _normalize_graph_path(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Neo4j attack-path row into the shape the UI expects.

    Neo4j row keys:
        resource_uid, resource_name, resource_type,
        threat_id, threat_severity, risk_score, verdict,
        mitre_techniques, node_names, rel_types, hops

    UI expected shape:
        id, title, description, severity, status, hops,
        steps: [{ resourceName, resourceType, resourceArn, technique }]
    """
    resource_uid = raw.get("resource_uid") or ""
    resource_name = raw.get("resource_name") or resource_uid.split("/")[-1]
    resource_type = raw.get("resource_type") or ""
    severity = (raw.get("threat_severity") or raw.get("severity") or "medium").lower()
    threat_id = raw.get("threat_id") or ""
    node_names = raw.get("node_names") or []
    rel_types = raw.get("rel_types") or []
    hops = raw.get("hops") or len(node_names) - 1 or 1
    mitre = raw.get("mitre_techniques") or []

    # Build a stable path ID from resource + threat
    path_id = hashlib.sha256(
        f"{resource_uid}|{threat_id}".encode()
    ).hexdigest()[:12]

    # Build steps from the node_names / rel_types arrays
    steps: List[Dict[str, Any]] = []
    for idx, name in enumerate(node_names):
        step: Dict[str, Any] = {
            "resourceName": name or "Unknown",
            "resourceType": "Internet" if idx == 0 and name == "Internet" else "",
            "resourceArn": "",
            "technique": rel_types[idx] if idx < len(rel_types) else "",
        }
        # Last step is the target resource
        if idx == len(node_names) - 1:
            step["resourceName"] = resource_name
            step["resourceType"] = resource_type
            step["resourceArn"] = resource_uid
            if mitre:
                tech = mitre[0] if isinstance(mitre[0], str) else mitre[0].get("technique_id", "") if isinstance(mitre[0], dict) else str(mitre[0])
                step["technique"] = tech
        steps.append(step)

    # If no steps were built (empty node_names), create a minimal two-step path
    if not steps:
        steps = [
            {"resourceName": "Internet", "resourceType": "Internet", "resourceArn": "", "technique": "EXPOSES"},
            {"resourceName": resource_name, "resourceType": resource_type, "resourceArn": resource_uid, "technique": ""},
        ]

    title = f"Internet → {resource_name}"
    if len(node_names) > 2:
        mid = " → ".join(n for n in node_names[1:-1] if n) or ""
        if mid:
            title = f"Internet → {mid} → {resource_name}"

    return {
        "id": f"AP-{path_id}",
        "title": title,
        "description": f"{severity.upper()} threat on {resource_type} '{resource_name}' reachable in {hops} hop(s)",
        "severity": severity,
        "status": "active",
        "hops": hops,
        "blastRadius": severity,
        "steps": steps,
    }


@router.get("/threats/attack-paths")
async def view_threat_attack_paths(
    tenant_id: str = Query(...),
    max_hops: int = Query(5, ge=1, le=20),
    min_severity: str = Query("medium"),
):
    """BFF view for attack paths page.

    Calls the threat engine graph endpoint for attack paths and returns
    KPIs (total, critical, high, active) plus the normalized path list.
    """

    results = await fetch_many([
        ("threat", "/api/v1/graph/attack-paths", {
            "tenant_id": tenant_id,
            "max_hops": str(max_hops),
            "min_severity": min_severity,
        }),
    ])

    paths_data = results[0]

    # Safely handle None
    if not isinstance(paths_data, (dict, list)):
        paths_data = {}

    # Extract paths list
    if isinstance(paths_data, list):
        raw_paths = paths_data
    else:
        raw_paths = (
            safe_get(paths_data, "attack_paths", [])
            or safe_get(paths_data, "paths", [])
            or safe_get(paths_data, "data", [])
        )
    if not isinstance(raw_paths, list):
        raw_paths = []

    paths = [_normalize_graph_path(p) for p in raw_paths]

    # Deduplicate by path id (same resource+threat → same card)
    seen = set()
    unique_paths = []
    for p in paths:
        if p["id"] not in seen:
            seen.add(p["id"])
            unique_paths.append(p)
    paths = unique_paths

    # KPIs
    total = len(paths)
    critical = sum(1 for p in paths if p.get("severity") == "critical")
    high = sum(1 for p in paths if p.get("severity") == "high")
    active = sum(1 for p in paths if p.get("severity") in ("critical", "high", "medium"))

    return {
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "active": active,
        },
        "attackPaths": paths,
    }
