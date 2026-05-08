"""BFF view: /threats/graph page.

Retrieves the security graph from the threat engine's Neo4j graph
and returns nodes + links in a UI-ready format for graph visualization.

Combines data from graph summary, attack paths (internet + all entry),
toxic combinations to build a complete graph with edges.

Two-layer edge model:
  path        — attacker traversal (ASSUMES, EXPOSES, STORES, CONNECTS_TO, ...)
  association — context (HAS_FINDING, HAS_THREAT, ENCRYPTED_BY, DEPENDS_ON, ...)
"""

import logging
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id, _parse_auth_context
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.threat_graph import ThreatGraphResponse, NodeSecurityResponse

logger = logging.getLogger("api-gateway.bff.threat_graph")

# ── CVE field stripping ──────────────────────────────────────────────────────

# Roles that may see KEV intelligence fields (in_kev, epss_score).
# tenant_admin + privileged roles only — analyst and viewer are excluded.
_CVE_PRIVILEGED_ROLES = {"tenant_admin", "org_admin", "platform_admin", "group_admin"}

CVE_SENSITIVE_FIELDS = {"in_kev", "epss_score"}


def _strip_cve_fields_for_role(cves: list, role: str) -> list:
    """Strip KEV intelligence fields for analyst and viewer roles.

    Args:
        cves:  List of CVE dicts returned from the threat engine.
        role:  Role name from AuthContext (e.g. "viewer", "analyst", "tenant_admin").

    Returns:
        Filtered list — in_kev and epss_score removed for unprivileged roles.
    """
    if role in _CVE_PRIVILEGED_ROLES:
        return cves
    return [
        {k: v for k, v in cve.items() if k not in CVE_SENSITIVE_FIELDS}
        for cve in cves
    ]

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _extract_short_name(uid: str) -> str:
    """Extract a short display name from an ARN or resource UID."""
    if "/" in uid:
        return uid.split("/")[-1]
    if ":" in uid:
        return uid.split(":")[-1]
    return uid


def _infer_edge_kind(rel_type: str) -> str:
    """Infer edge_kind from relationship type name if not already set."""
    _ASSOCIATION_TYPES = {
        "HAS_FINDING", "HAS_THREAT", "AFFECTED_BY", "ENCRYPTED_BY",
        "LOGS_TO", "PROTECTED_BY", "DEPENDS_ON", "PROTECTS",
        "OWNS", "MEMBER_OF", "MONITORED_BY",
    }
    return "association" if rel_type.upper() in _ASSOCIATION_TYPES else "path"


def _build_orca_paths(raw_paths: list, graph_nodes: list) -> list:
    """Attach node_graph_ids, entry_point, entry_type, and total_risk to each orca path.

    Builds a reverse-lookup map from resource_uid to graph node id using the
    nodes returned by the subgraph endpoint, then annotates every orca path with
    the graph node IDs that correspond to its traversal nodes.  The client uses
    this to build a highlight set without performing UID→ID resolution itself.

    Added contract fields (per BFF-contract fix):
      entry_point  — resource_uid of the first node in the path
      entry_type   — resource_type of the first node in the path
      total_risk   — sum of risk_score across all path nodes; falls back to the
                     path-level risk_score if node-level scores are unavailable

    Args:
        raw_paths:   List of raw orca path dicts from the threat engine.
        graph_nodes: List of graph node dicts as returned in the BFF response
                     (each node must have "id" and optionally "uid").

    Returns:
        New list — each path dict extended with "node_graph_ids", "entry_point",
        "entry_type", and "total_risk" (may be shorter than path.nodes if some
        nodes were pruned from the subgraph).
    """
    # Build reverse-lookup: resource_uid → graph node id (server-side only)
    uid_to_graph_id: Dict[str, str] = {
        node["uid"]: node["id"]
        for node in graph_nodes
        if node.get("uid") and node.get("id")
    }

    result = []
    for path in raw_paths:
        path_nodes = path.get("nodes") or []
        node_graph_ids = []
        for node in path_nodes:
            gid = uid_to_graph_id.get(node.get("uid"))
            if gid:
                node_graph_ids.append(gid)

        # entry_point / entry_type from the first node in the traversal
        first_node = path_nodes[0] if path_nodes else {}
        entry_point = first_node.get("uid") or first_node.get("resource_uid") or None
        entry_type = first_node.get("resource_type") or first_node.get("type") or None

        # total_risk — sum node-level scores, fall back to path-level risk_score
        node_risk_sum = sum(
            (n.get("risk_score") or n.get("riskScore") or 0)
            for n in path_nodes
            if isinstance(n, dict)
        )
        total_risk = node_risk_sum if node_risk_sum > 0 else (path.get("risk_score") or 0)

        result.append({
            **path,
            "node_graph_ids": node_graph_ids,
            "entry_point": entry_point,
            "entry_type": entry_type,
            "total_risk": total_risk,
        })
    return result


async def _check_cve_nodes_exist(tenant_id: str, fwd_headers: Optional[Dict[str, str]]) -> bool:
    """Return True only if ≥1 CVE node exists for this tenant in Neo4j.

    The BFF does not have direct Neo4j access — it queries the threat engine's
    /graph/summary endpoint and checks cve_node_count.  Fail-safe: returns False
    on any error so the CVE Risk view is gated until explicitly confirmed live.

    Args:
        tenant_id:   Tenant ID to scope the check.
        fwd_headers: Forwarded auth headers for the threat engine call.

    Returns:
        True if at least one CVE node exists for this tenant, False otherwise.
    """
    try:
        results = await fetch_many([
            ("threat", "/api/v1/graph/summary", {"tenant_id": tenant_id}),
        ], auth_headers=fwd_headers)
        summary = results[0] if results else None
        if not isinstance(summary, dict):
            return False
        node_counts = summary.get("node_counts") or {}
        if isinstance(node_counts, dict):
            return int(node_counts.get("CVE", 0)) > 0
        return False
    except Exception as exc:
        logger.warning("_check_cve_nodes_exist failed (fail-safe False): %s", exc)
        return False


def _normalize_node(node: dict) -> dict:
    """Normalize a node dict to the canonical snake_case contract.

    Accepts both camelCase legacy keys (riskScore, threatCount) and snake_case
    keys from Neo4j subgraph responses, and always emits snake_case to the UI.
    CVE-specific fields are included as-is here; role-based stripping of
    in_kev / epss_score is done in the view layer before returning.

    Args:
        node: Raw node dict from any source (path builder or subgraph endpoint).

    Returns:
        Normalized node dict with all required contract fields present.
    """
    uid = node.get("uid") or node.get("resource_uid") or node.get("id") or ""
    resource_name = node.get("resource_name") or node.get("name")
    resource_type = node.get("resource_type") or node.get("type") or ""
    label = (
        resource_name
        or resource_type
        or (_extract_short_name(uid) if uid else "Unknown")
    )

    # Accept camelCase fallbacks from the path builder's own output
    risk_score = (
        node.get("risk_score")
        if node.get("risk_score") is not None
        else node.get("riskScore") or 0
    )
    threat_count = (
        node.get("threat_count")
        if node.get("threat_count") is not None
        else node.get("threatCount") or 0
    )

    # Severity — prefer explicit field, then derive from risk_score
    severity = (node.get("severity") or node.get("threat_severity") or "").lower()
    threat_severity = (node.get("threat_severity") or severity or "").lower()
    has_threat = bool(threat_count > 0)

    # Finding breakdown
    findings: list = node.get("findings") or []
    finding_count = node.get("finding_count") or len(findings)
    finding_severity_breakdown: dict = node.get("finding_severity_breakdown") or {}

    # ARN — probe multiple possible field names from Neo4j props
    arn = node.get("arn") or node.get("resource_arn") or None

    normalized = {
        "id": node.get("id") or uid,
        "uid": uid,
        "label": node.get("label") or label,
        "type": resource_type,
        "risk_score": risk_score,
        "threat_count": threat_count,
        "severity": severity,
        "has_threat": has_threat,
        "threat_severity": threat_severity,
        "arn": arn,
        "description": node.get("description") or None,
        "provider": node.get("provider") or None,
        "region": node.get("region") or None,
        "account": node.get("account") or node.get("account_id") or None,
        "findings": findings,
        "finding_count": finding_count,
        "finding_severity_breakdown": finding_severity_breakdown,
    }

    # CVE-specific fields — present only for CVE-typed nodes
    node_type_upper = str(node.get("type") or resource_type).upper()
    if node_type_upper == "CVE":
        normalized["cve_id"] = node.get("cve_id") or node.get("id") or None
        normalized["cvss_score"] = node.get("cvss_score") or None
        normalized["epss_score"] = node.get("epss_score") or None
        normalized["in_kev"] = node.get("in_kev") or False
        normalized["published_date"] = node.get("published_date") or None

    return normalized


def _normalize_edge(edge: dict) -> dict:
    """Ensure every edge has the required contract fields.

    Required: source, target, edge_kind, relationship.
    The legacy 'type' key carries the Neo4j relationship type (e.g. EXPOSES);
    we keep it for backward compat and also expose it as 'relationship'.

    Args:
        edge: Raw edge dict from any source.

    Returns:
        Edge dict with all required fields present.
    """
    rel_type = edge.get("type") or edge.get("relationship") or "RELATED_TO"
    edge_kind = edge.get("edge_kind") or _infer_edge_kind(rel_type)
    return {
        **edge,
        "source": edge.get("source") or "",
        "target": edge.get("target") or "",
        "edge_kind": edge_kind,
        "relationship": edge.get("relationship") or rel_type,
    }


def _build_graph_from_paths(
    internet_paths: List[dict],
    all_paths: List[dict],
    toxic_combos: List[dict],
) -> tuple:
    """Build nodes and edges from attack paths + toxic combinations.

    Returns (nodes, edges). All nodes are normalized via _normalize_node so that
    the response contract is consistent regardless of whether the primary
    subgraph endpoint or this fallback path is used.
    Edges are normalized via _normalize_edge.
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
                raw = {
                    "id": node_id,
                    "uid": node_id,
                    "label": name if not is_last else resource_name,
                    "type": (
                        "Internet" if name == "Internet"
                        else resource_type if is_last
                        else "ec2.security-group"
                    ),
                    "risk_score": risk_score if is_last else 0,
                    "severity": severity if is_last else "",
                    "threat_count": 1 if is_last else 0,
                }
                node_map[node_id] = _normalize_node(raw)
            elif is_last:
                existing = node_map[node_id]
                existing["threat_count"] = existing.get("threat_count", 0) + 1
                existing["has_threat"] = True
                if risk_score > existing.get("risk_score", 0):
                    existing["risk_score"] = risk_score
                    existing["severity"] = severity
                    existing["threat_severity"] = severity

            if prev_id is not None:
                rel = rel_types[idx - 1] if idx - 1 < len(rel_types) else "CONNECTS_TO"
                edge_key = f"{prev_id}|{node_id}|{rel}"
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append(_normalize_edge({
                        "source": prev_id,
                        "target": node_id,
                        "type": rel,
                        "edge_kind": _infer_edge_kind(rel),
                    }))
            prev_id = node_id

        # Standalone resource (no path nodes)
        if not node_names and resource_uid:
            if resource_uid not in node_map:
                raw = {
                    "id": resource_uid,
                    "uid": resource_uid,
                    "label": resource_name,
                    "type": resource_type,
                    "risk_score": risk_score,
                    "severity": severity,
                    "threat_count": 1,
                }
                node_map[resource_uid] = _normalize_node(raw)

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
        combo_threat_count = combo.get("threat_count", 0)

        if resource_uid not in node_map:
            raw = {
                "id": resource_uid,
                "uid": resource_uid,
                "label": resource_name,
                "type": resource_type,
                "risk_score": risk_score,
                "severity": (
                    "critical" if risk_score >= 80
                    else "high" if risk_score >= 60
                    else "medium"
                ),
                "threat_count": combo_threat_count,
            }
            node_map[resource_uid] = _normalize_node(raw)

        # Edges from threat details to resource — association edges
        details = combo.get("threat_details") or []
        for td in details:
            det_id = td.get("detection_id", "") if isinstance(td, dict) else ""
            if det_id and det_id not in node_map:
                raw = {
                    "id": det_id,
                    "uid": det_id,
                    "label": (td.get("rule_name") or det_id)[:40],
                    "type": "threat",
                    "risk_score": td.get("risk_score", 0) if isinstance(td, dict) else 0,
                    "severity": td.get("severity", "") if isinstance(td, dict) else "",
                    "threat_count": 0,
                }
                node_map[det_id] = _normalize_node(raw)
            if det_id:
                edge_key = f"{det_id}|{resource_uid}|AFFECTS"
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append(_normalize_edge({
                        "source": det_id,
                        "target": resource_uid,
                        "type": "AFFECTS",
                        "edge_kind": "association",
                    }))

    return list(node_map.values()), edges


@router.get("/threats/graph", response_model=ThreatGraphResponse, response_model_exclude_none=False)
async def view_threat_graph(
    request: Request,
):
    """BFF view for the threat graph visualization page.

    Primary: Wiz-style subgraph from Neo4j (resource nodes + relationship edges).
    Fallback: builds graph from attack paths if subgraph endpoint is unavailable.

    Edges include edge_kind="path"|"association" for two-layer rendering.
    Also fetches orca_paths for the Orca-style attack path cards.

    New fields (GRAPH-BFF-01):
      orca_paths[n].node_graph_ids — graph node IDs for path highlight
      graph_capabilities.has_cve_nodes — feature flag for CVE Risk view
    """

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("threat_graph")

    # Resolve role for CVE field stripping — fail-safe to most restrictive
    auth_ctx = _parse_auth_context(request)
    role = auth_ctx.role if auth_ctx else "viewer"

    # Only call summary + subgraph — attack-paths and orca-paths hit Neo4j OOM
    # at the 250MB transaction memory limit when run concurrently with subgraph.
    results = await fetch_many([
        ("threat", "/api/v1/graph/summary", {
            "tenant_id": tenant_id,
        }),
        ("threat", "/api/v1/graph/subgraph", {
            "tenant_id": tenant_id,
            "max_nodes": "300",
        }),
    ], auth_headers=fwd_headers)

    summary_data, subgraph_data = results

    if not isinstance(summary_data, dict):
        summary_data = {}
    if not isinstance(subgraph_data, dict):
        subgraph_data = {}

    # Primary: use subgraph (Wiz-style topology)
    sub_nodes = safe_get(subgraph_data, "nodes", [])
    sub_edges = safe_get(subgraph_data, "edges", [])

    if isinstance(sub_nodes, list) and len(sub_nodes) > 0:
        # Normalize all nodes to the snake_case contract; strip CVE intel fields
        # for analyst / viewer roles (STRIDE: Information Disclosure gate).
        nodes = []
        for raw_node in sub_nodes:
            normalized = _normalize_node(raw_node)
            if normalized.get("type", "").upper() == "CVE":
                if role not in _CVE_PRIVILEGED_ROLES:
                    normalized.pop("in_kev", None)
                    normalized.pop("epss_score", None)
            nodes.append(normalized)

        raw_edges = sub_edges if isinstance(sub_edges, list) else []
        edges = [_normalize_edge(e) for e in raw_edges]
    else:
        nodes, edges = [], []

    # Orca paths disabled — /graph/orca-paths causes Neo4j OOM at 250MB limit.
    # When re-enabled, pass nodes so _build_orca_paths can annotate node_graph_ids.
    raw_orca_paths: list = []
    orca_paths = _build_orca_paths(raw_orca_paths, nodes)

    # Feature flag: gate CVE Risk view until GRAPH-S2-03 ships CVE nodes.
    # Reuses the already-fetched summary_data — no extra network call needed.
    node_counts = safe_get(summary_data, "node_counts", {})
    has_cve: bool = bool(
        isinstance(node_counts, dict) and int(node_counts.get("CVE", 0)) > 0
    )

    # KPIs
    rel_counts = safe_get(summary_data, "relationship_counts", {})

    total_nodes = (
        sum(node_counts.values()) if isinstance(node_counts, dict) and node_counts
        else len(nodes)
    )
    total_edges = (
        sum(rel_counts.values()) if isinstance(rel_counts, dict) and rel_counts
        else len(edges)
    )

    # risk_score is snake_case after normalization
    risk_scores = [n.get("risk_score", 0) for n in nodes if n.get("risk_score", 0) > 0]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    internet_exposed = sum(
        1 for e in edges if e.get("relationship") == "EXPOSES" or e.get("type") == "EXPOSES"
    )

    path_edges = sum(1 for e in edges if e.get("edge_kind") == "path")
    assoc_edges = sum(1 for e in edges if e.get("edge_kind") == "association")

    return {
        "kpi": {
            "nodes": total_nodes,
            "edges": total_edges,
            "avgRisk": avg_risk,
            "internetExposed": internet_exposed,
            "pathEdges": path_edges,
            "associationEdges": assoc_edges,
            "orcaPaths": len(orca_paths),
        },
        "nodes": nodes,
        "links": edges,
        "orca_paths": orca_paths,
        "graph_capabilities": {
            "has_cve_nodes": has_cve,
        },
        "filterSchema": [
            {
                "key": "attack_paths",
                "label": "Attack Paths",
                "description": "Nodes on active attack paths",
            },
            {
                "key": "high_risk",
                "label": "High Risk",
                "description": "Nodes with risk_score >= 70",
            },
            {
                "key": "cve_risk",
                "label": "CVE Risk",
                "description": "Resources with CVE exposure",
            },
            {
                "key": "internet_risk",
                "label": "Internet Exposed",
                "description": "Resources exposed to internet",
            },
            {
                "key": "full_graph",
                "label": "All",
                "description": "Show all nodes and edges",
            },
        ],
        "_meta": meta.to_dict(),
    }


@router.get("/threats/graph/node-security/{resource_uid:path}", response_model=NodeSecurityResponse, response_model_exclude_none=False)
async def view_threat_graph_node_security(
    resource_uid: str,
    request: Request,
):
    """BFF view for graph node security details (CVE list, findings, posture).

    Proxies GET /api/v1/graph/node/{resource_uid} from the threat engine and
    strips in_kev / epss_score from CVE objects for analyst and viewer roles
    per RBAC policy (STRIDE: Information Disclosure — KEV intelligence is
    restricted to tenant_admin and above).

    Args:
        resource_uid: Resource UID of the graph node to fetch security details for.

    Returns:
        Node security payload with cves[] field role-stripped.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    # Resolve role for CVE field stripping — fail-safe to most restrictive
    auth_ctx = _parse_auth_context(request)
    role = auth_ctx.role if auth_ctx else "viewer"

    results = await fetch_many([
        ("threat", f"/api/v1/graph/resource/{resource_uid}", {"tenant_id": tenant_id}),
    ], auth_headers=fwd_headers)

    data = results[0] if results else {}
    if not isinstance(data, dict):
        data = {}

    # Map engine response to frontend-expected shape.
    # Engine returns: resource, neighbors, threats, findings, *_count
    # Frontend NodeInvestigationPanel expects: configProperties, failCount,
    #   cves, cveCount, criticalCveCount (plus passthrough of other fields).
    findings_raw = data.get("findings") or []
    threats_raw = data.get("threats") or []
    resource_raw = data.get("resource") or {}

    # configProperties: map HAS_FINDING nodes from Neo4j.
    # Each finding in the graph represents a FAIL check result.
    config_props = [
        {
            "check_id": f.get("rule_id", ""),
            "title": f.get("title", f.get("rule_id", "")),
            "result": "FAIL",
            "severity": f.get("severity", "medium"),
            "service": f.get("service", ""),
        }
        for f in findings_raw
        if isinstance(f, dict)
    ]

    # Also extract prop_* properties written by _expand_config_properties
    # when the graph has been built with posture enrichment.
    for key, val in resource_raw.items():
        if key.startswith("prop_") and key.endswith("_result"):
            rule_id = key[len("prop_"):-len("_result")]
            title_key = f"prop_{rule_id}_title"
            svc_key = f"prop_{rule_id}_service"
            config_props.append({
                "check_id": rule_id,
                "title": resource_raw.get(title_key, rule_id),
                "result": str(val).upper() if val else "UNKNOWN",
                "severity": resource_raw.get(f"prop_{rule_id}_severity", "medium"),
                "service": resource_raw.get(svc_key, ""),
            })

    fail_count = sum(1 for p in config_props if p.get("result") == "FAIL")

    # CVEs: extract from threats that carry CVE metadata.
    cves_raw = [
        t for t in threats_raw
        if isinstance(t, dict) and t.get("cve_id")
    ]
    # Role-strip KEV / EPSS before returning
    cves_stripped = _strip_cve_fields_for_role(cves_raw, role)
    critical_cve_count = sum(
        1 for c in cves_stripped
        if str(c.get("severity", "")).upper() == "CRITICAL"
    )

    return {
        **data,
        "configProperties": config_props,
        "failCount": fail_count,
        "cves": cves_stripped,
        "cveCount": len(cves_stripped),
        "criticalCveCount": critical_cve_count,
        # Keep node_uid for panel header rendering
        "node_uid": resource_raw.get("uid") or resource_uid,
    }


@router.get("/threats/graph/filtered")
async def view_threat_graph_filtered(
    request: Request,
    resource_type: Optional[str] = Query(None),
    security_status: Optional[str] = Query(None),
    connected_to: Optional[str] = Query(None),
    via_edge: Optional[str] = Query(None),
    edge_kind: Optional[str] = Query(None, description="path | association | omit for all"),
    within_hops: int = Query(2, ge=0, le=5),
    limit: int = Query(300, ge=1, le=1000),
):
    """Real-time filtered subgraph proxy → threat engine /graph/explore.

    Called by the frontend Graph Explorer on every filter change (debounced 300ms).
    Returns {nodes, edges, total_nodes, total_edges, matched_nodes, cypher_summary}
    with edge_kind on every edge for two-layer rendering.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    params: Dict[str, str] = {"tenant_id": tenant_id, "limit": str(limit)}
    if resource_type:
        params["resource_type"] = resource_type
    if security_status:
        params["security_status"] = security_status
    if connected_to:
        params["connected_to"] = connected_to
    if via_edge:
        params["via_edge"] = via_edge
    if edge_kind:
        params["edge_kind"] = edge_kind
    params["within_hops"] = str(within_hops)

    results = await fetch_many([
        ("threat", "/api/v1/graph/explore", params)
    ], auth_headers=fwd_headers)
    data = results[0] if results else {}
    if not isinstance(data, dict):
        data = {}

    # Normalize nodes (snake_case contract) and edges (required fields)
    raw_nodes = data.get("nodes") or []
    data["nodes"] = [_normalize_node(n) for n in raw_nodes]

    raw_edges = data.get("edges") or []
    data["edges"] = [_normalize_edge(e) for e in raw_edges]

    return data