"""BFF view: /threats/graph page.

Retrieves the security graph from the threat engine's Neo4j graph
and returns nodes + links in a UI-ready format for graph visualization.

Combines data from graph summary, attack paths (internet + all entry),
toxic combinations to build a complete graph with edges.
"""

from typing import Dict, List, Set

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _extract_short_name(uid: str) -> str:
    """Extract a short display name from an ARN or resource UID."""
    if "/" in uid:
        return uid.split("/")[-1]
    if ":" in uid:
        return uid.split(":")[-1]
    return uid


def _build_graph_from_paths(
    internet_paths: List[dict],
    all_paths: List[dict],
    toxic_combos: List[dict],
) -> tuple:
    """Build nodes and edges from attack paths + toxic combinations.

    Returns (nodes, edges).
    """
    node_map: Dict[str, dict] = {}
    edges: List[dict] = []
    edge_set: Set[str] = set()

    def _add_path(ap: dict) -> None:
        resource_uid = ap.get("resource_uid", "")
        resource_name = (
            ap.get("resource_name")
            or (_extract_short_name(resource_uid) if resource_uid else "Unknown")
        )
        resource_type = ap.get("resource_type", "")
        severity = (ap.get("threat_severity") or ap.get("severity") or "medium").lower()
        risk_score = ap.get("risk_score") or 0

        node_names = ap.get("node_names") or []
        rel_types = ap.get("rel_types") or []

        prev_id = None
        for idx, name in enumerate(node_names):
            is_last = idx == len(node_names) - 1
            if is_last and resource_uid:
                node_id = resource_uid
            elif name == "Internet":
                node_id = "Internet"
            else:
                node_id = name or f"node-{idx}"

            if node_id not in node_map:
                node_map[node_id] = {
                    "id": node_id,
                    "label": name if not is_last else resource_name,
                    "type": (
                        "Internet" if name == "Internet"
                        else resource_type if is_last
                        else "ec2.security-group"
                    ),
                    "riskScore": risk_score if is_last else 0,
                    "severity": severity if is_last else "",
                    "threatCount": 1 if is_last else 0,
                }
            elif is_last:
                existing = node_map[node_id]
                existing["threatCount"] = existing.get("threatCount", 0) + 1
                if risk_score > existing.get("riskScore", 0):
                    existing["riskScore"] = risk_score
                    existing["severity"] = severity

            if prev_id is not None:
                rel = rel_types[idx - 1] if idx - 1 < len(rel_types) else "CONNECTS_TO"
                edge_key = f"{prev_id}|{node_id}|{rel}"
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({
                        "source": prev_id,
                        "target": node_id,
                        "type": rel,
                    })
            prev_id = node_id

        # Standalone resource (no path nodes)
        if not node_names and resource_uid:
            if resource_uid not in node_map:
                node_map[resource_uid] = {
                    "id": resource_uid,
                    "label": resource_name,
                    "type": resource_type,
                    "riskScore": risk_score,
                    "severity": severity,
                    "threatCount": 1,
                }

    # Build from internet paths and all-entry paths
    for ap in internet_paths:
        _add_path(ap)
    for ap in all_paths:
        _add_path(ap)

    # Toxic combinations
    for combo in toxic_combos:
        resource_uid = combo.get("resource_uid", "")
        if not resource_uid:
            continue
        resource_name = combo.get("resource_name") or _extract_short_name(resource_uid)
        resource_type = combo.get("resource_type", "")
        risk_score = combo.get("risk_score") or combo.get("toxicity_score") or 0

        if resource_uid not in node_map:
            node_map[resource_uid] = {
                "id": resource_uid,
                "label": resource_name,
                "type": resource_type,
                "riskScore": risk_score,
                "severity": (
                    "critical" if risk_score >= 80
                    else "high" if risk_score >= 60
                    else "medium"
                ),
                "threatCount": combo.get("threat_count", 0),
            }

        # Edges from threat details to resource
        details = combo.get("threat_details") or []
        for td in details:
            det_id = td.get("detection_id", "") if isinstance(td, dict) else ""
            if det_id and det_id not in node_map:
                node_map[det_id] = {
                    "id": det_id,
                    "label": (td.get("rule_name") or det_id)[:40],
                    "type": "threat",
                    "riskScore": td.get("risk_score", 0) if isinstance(td, dict) else 0,
                    "severity": td.get("severity", "") if isinstance(td, dict) else "",
                    "threatCount": 0,
                }
            if det_id:
                edge_key = f"{det_id}|{resource_uid}|AFFECTS"
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({
                        "source": det_id,
                        "target": resource_uid,
                        "type": "AFFECTS",
                    })

    return list(node_map.values()), edges


@router.get("/threats/graph")
async def view_threat_graph(
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
):
    """BFF view for the threat graph visualization page.

    Primary: Wiz-style subgraph from Neo4j (resource nodes + relationship edges).
    Fallback: builds graph from attack paths if subgraph endpoint is unavailable.
    """

    results = await fetch_many([
        ("threat", "/api/v1/graph/summary", {
            "tenant_id": tenant_id,
        }),
        ("threat", "/api/v1/graph/subgraph", {
            "tenant_id": tenant_id,
            "max_nodes": "300",
        }),
        ("threat", "/api/v1/graph/attack-paths", {
            "tenant_id": tenant_id,
            "max_hops": "5",
            "min_severity": "low",
        }),
        ("threat", "/api/v1/graph/attack-paths", {
            "tenant_id": tenant_id,
            "max_hops": "5",
            "min_severity": "low",
            "entry_point": "all",
        }),
    ])

    summary_data, subgraph_data, inet_paths_data, all_paths_data = results

    if not isinstance(summary_data, dict):
        summary_data = {}
    if not isinstance(subgraph_data, dict):
        subgraph_data = {}

    # Primary: use subgraph (Wiz-style topology)
    sub_nodes = safe_get(subgraph_data, "nodes", [])
    sub_edges = safe_get(subgraph_data, "edges", [])

    if isinstance(sub_nodes, list) and len(sub_nodes) > 0:
        nodes = sub_nodes
        edges = sub_edges if isinstance(sub_edges, list) else []
    else:
        # Fallback: build from attack paths
        if not isinstance(inet_paths_data, dict):
            inet_paths_data = {}
        if not isinstance(all_paths_data, dict):
            all_paths_data = {}

        inet_paths = safe_get(inet_paths_data, "attack_paths", []) or []
        if not isinstance(inet_paths, list):
            inet_paths = []
        all_paths = safe_get(all_paths_data, "attack_paths", []) or []
        if not isinstance(all_paths, list):
            all_paths = []

        nodes, edges = _build_graph_from_paths(inet_paths, all_paths, [])

    # KPIs
    node_counts = safe_get(summary_data, "node_counts", {})
    rel_counts = safe_get(summary_data, "relationship_counts", {})

    total_nodes = (
        sum(node_counts.values()) if isinstance(node_counts, dict) and node_counts
        else len(nodes)
    )
    total_edges = (
        sum(rel_counts.values()) if isinstance(rel_counts, dict) and rel_counts
        else len(edges)
    )

    risk_scores = [n.get("riskScore", 0) for n in nodes if n.get("riskScore", 0) > 0]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    internet_exposed = sum(
        1 for e in edges if e.get("type") == "EXPOSES"
    )

    return {
        "kpi": {
            "nodes": total_nodes,
            "edges": total_edges,
            "avgRisk": avg_risk,
            "internetExposed": internet_exposed,
        },
        "nodes": nodes,
        "links": edges,
    }
