"""BFF view: /threats/attack-paths page.

Merges two sources for maximum path coverage:
  1. PostgreSQL threat_analysis (pre-computed, scored, chain-typed)
  2. Neo4j orca_attack_paths (live graph traversal, per-node enrichment)

Neo4j paths bridge the gap when asset_category seeding is sparse or
relationship attack_path_category mapping is incomplete.
"""

import hashlib
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


# ── Chain type labels ────────────────────────────────────────────────────────

CHAIN_TYPE_LABELS = {
    "internet_to_secrets": "Internet → Secrets",
    "internet_to_data": "Internet → Data Store",
    "internet_to_identity": "Internet → Identity",
    "internet_to_privilege_escalation": "Internet → Privilege Escalation",
    "internet_to_code_execution": "Internet → Code Execution",
    "internet_to_lateral_movement": "Internet → Lateral Movement",
    "internet_to_compute": "Internet → Compute",
    "internet_to_data_access": "Internet → Data Access",
    "internet_to_generic": "Internet → Resource",
    "internal_secrets": "Internal → Secrets",
    "internal_data": "Internal → Data Store",
    "internal_identity": "Internal → Identity",
    "internal_privilege_escalation": "Internal Privilege Escalation",
    "internal_code_execution": "Internal Code Execution",
    "internal_lateral_movement": "Internal Lateral Movement",
    "internal_compute": "Internal → Compute",
    "internal_data_access": "Internal Data Access",
    "internal_generic": "Internal Path",
}


def _severity_from_score(score: int) -> str:
    """Derive severity label from path score."""
    if score >= 70:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _normalize_path(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an analyzer attack path into UI shape."""
    chain_type = raw.get("chain_type", "unknown")
    score = raw.get("path_score", 0)
    severity = _severity_from_score(score)
    hops = raw.get("hops", [])
    depth = raw.get("depth", len(hops))
    entry = raw.get("entry_point", "")
    target = raw.get("target", "")
    target_cat = raw.get("target_category", "")
    mitre = raw.get("mitre_techniques", [])

    entry_name = entry.split("/")[-1] if "/" in entry else entry.split(":")[-1] if ":" in entry else entry
    target_name = target.split("/")[-1] if "/" in target else target.split(":")[-1] if ":" in target else target
    title = CHAIN_TYPE_LABELS.get(chain_type, chain_type.replace("_", " ").title())

    # Build a stable ID
    path_id = hashlib.sha256(
        f"{entry}|{target}|{chain_type}".encode()
    ).hexdigest()[:12]

    # Build steps from hops
    steps = []
    for h in hops:
        if not isinstance(h, dict):
            continue
        steps.append({
            "from": h.get("from", ""),
            "to": h.get("to", ""),
            "relationship": h.get("rel", ""),
            "category": h.get("category", ""),
        })

    return {
        "id": f"AP-{path_id}",
        "title": title,
        "description": f"{entry_name} → {target_name} ({depth} hops, score {score})",
        "chainType": chain_type,
        "severity": severity,
        "pathScore": score,
        "depth": depth,
        "entryPoint": entry,
        "entryPointName": entry_name,
        "target": target,
        "targetName": target_name,
        "targetCategory": target_cat,
        "steps": steps,
        # Detection context
        "detectionId": raw.get("detection_id", ""),
        "resourceUid": raw.get("resource_uid", ""),
        "resourceType": raw.get("resource_type", ""),
        "riskScore": raw.get("risk_score", 0),
        "provider": (raw.get("provider") or "").upper() or "--",
        "accountId": raw.get("account_id", ""),
        "region": raw.get("region", ""),
        "isInternetReachable": raw.get("is_internet_reachable", False),
        "mitreTechniques": mitre,
    }


def _chain_type_from_orca(path: Dict[str, Any]) -> str:
    """Infer chain_type from an orca path's entry + target."""
    is_internet = path.get("entry_type") == "Internet" or path.get("entry_point") == "Internet"
    target_type = (path.get("target_type") or "").lower()

    if "s3" in target_type or "storage" in target_type or "bucket" in target_type:
        sub = "data"
    elif "secret" in target_type or "ssm" in target_type or "kms" in target_type:
        sub = "secrets"
    elif "iam" in target_type or "role" in target_type or "user" in target_type:
        sub = "identity"
    elif "ec2" in target_type or "lambda" in target_type or "ecs" in target_type:
        sub = "compute"
    elif "rds" in target_type or "dynamo" in target_type or "database" in target_type:
        sub = "data_access"
    else:
        sub = "generic"

    prefix = "internet_to" if is_internet else "internal"
    return f"{prefix}_{sub}"


def _normalize_orca_path(op: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Neo4j orca path into the same UI shape as _normalize_path."""
    path_id = f"NEO-{op.get('path_id', '')}"
    score = op.get("total_risk") or 0
    severity = _severity_from_score(score)
    nodes = op.get("nodes") or []
    edges = op.get("edges") or []
    is_internet = op.get("entry_type") == "Internet" or op.get("entry_point") == "Internet"
    chain_type = _chain_type_from_orca(op)

    entry_name = (nodes[0].get("name") or nodes[0].get("uid") or "").split("/")[-1].split(":")[-1] if nodes else ""
    target_name = (nodes[-1].get("name") or nodes[-1].get("uid") or "").split("/")[-1].split(":")[-1] if nodes else ""

    # Convert neo4j nodes → steps (from/to pairs)
    steps: List[Dict[str, Any]] = []
    for i, edge in enumerate(edges):
        from_node = nodes[i] if i < len(nodes) else {}
        to_node = nodes[i + 1] if i + 1 < len(nodes) else {}
        steps.append({
            "from": (from_node.get("name") or from_node.get("uid") or ""),
            "to": (to_node.get("name") or to_node.get("uid") or ""),
            "relationship": edge.get("type") or edge.get("kind") or "",
            "category": edge.get("category") or "",
            # Per-node enrichment: attach to 'to' node
            "toNodeFindingCount": to_node.get("finding_count") or 0,
            "toNodeThreatCount": to_node.get("threat_count") or 0,
            "toNodeFindings": to_node.get("findings") or [],
            "toNodeThreats": to_node.get("threats") or [],
            "toNodeRiskScore": to_node.get("risk_score") or 0,
        })

    # Also embed enriched node list directly so UI can render per-node badges
    enriched_nodes = [
        {
            "label": (n.get("name") or n.get("uid") or "").split("/")[-1].split(":")[-1],
            "fullLabel": n.get("name") or n.get("uid") or "",
            "type": n.get("type") or "",
            "riskScore": n.get("risk_score") or 0,
            "findingCount": n.get("finding_count") or 0,
            "threatCount": n.get("threat_count") or 0,
            "threatSeverity": n.get("threat_severity"),
            "findings": n.get("findings") or [],
            "threats": n.get("threats") or [],
        }
        for n in nodes
    ]

    return {
        "id": f"AP-{path_id}",
        "title": CHAIN_TYPE_LABELS.get(chain_type, chain_type.replace("_", " ").title()),
        "description": f"{entry_name} → {target_name} ({op.get('hops', 0)} hops, risk {score})",
        "chainType": chain_type,
        "severity": severity,
        "pathScore": score,
        "depth": op.get("hops") or len(edges),
        "entryPoint": op.get("entry_point") or "",
        "entryPointName": entry_name,
        "target": op.get("target_uid") or "",
        "targetName": target_name,
        "targetCategory": "",
        "steps": steps,
        "nodes": enriched_nodes,
        "detectionId": "",
        "resourceUid": op.get("target_uid") or "",
        "resourceType": op.get("target_type") or "",
        "riskScore": score,
        "provider": "",
        "accountId": "",
        "region": "",
        "isInternetReachable": is_internet,
        "mitreTechniques": [],
        "source": "neo4j",
    }


@router.get("/threats/attack-paths")
async def view_threat_attack_paths(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    min_path_score: int = Query(0, ge=0, le=100),
):
    """BFF view for attack paths page — Orca-style.

    Merges PostgreSQL pre-computed paths + Neo4j live graph traversal.
    Neo4j paths include per-node finding_count and threat_count for badge rendering.
    """

    pg_params: Dict[str, str] = {"tenant_id": tenant_id, "limit": "500"}
    if scan_run_id:
        pg_params["scan_run_id"] = scan_run_id
    if min_path_score:
        pg_params["min_path_score"] = str(min_path_score)

    results = await fetch_many([
        ("threat", "/api/v1/threat/analysis/attack-paths", pg_params),
        ("threat", "/api/v1/graph/orca-paths", {
            "tenant_id": tenant_id,
            "max_hops": "6",
            "min_severity": "medium",
        }),
    ])

    pg_raw, neo_raw = results[0], results[1]

    # PostgreSQL paths
    if not isinstance(pg_raw, dict):
        pg_raw = {}
    raw_paths = safe_get(pg_raw, "attack_paths", [])
    if not isinstance(raw_paths, list):
        raw_paths = []
    summary = safe_get(pg_raw, "summary", {})
    pg_paths = [_normalize_path(p) for p in raw_paths if isinstance(p, dict)]

    # Neo4j paths
    if not isinstance(neo_raw, dict):
        neo_raw = {}
    orca_list = neo_raw.get("paths") or []
    if not isinstance(orca_list, list):
        orca_list = []
    neo_paths = [_normalize_orca_path(p) for p in orca_list if isinstance(p, dict)]

    # Merge — Neo4j paths first (richer, per-node data), then PG fills any unique gaps
    all_paths = neo_paths + pg_paths

    # Deduplicate by id
    seen: set = set()
    paths: List[Dict[str, Any]] = []
    for p in all_paths:
        if p["id"] not in seen:
            seen.add(p["id"])
            paths.append(p)

    # KPIs
    total = len(paths)
    critical = sum(1 for p in paths if p["severity"] == "critical")
    high = sum(1 for p in paths if p["severity"] == "high")
    internet = sum(1 for p in paths if p.get("isInternetReachable"))

    # Chain type breakdown — merge pg summary with actual paths
    chain_types: Dict[str, int] = {}
    for t, c in (safe_get(summary, "chain_types", {}) or {}).items():
        chain_types[t] = chain_types.get(t, 0) + c
    for p in neo_paths:
        ct = p.get("chainType", "")
        if ct:
            chain_types[ct] = chain_types.get(ct, 0) + 1

    return {
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "internetReachable": internet,
        },
        "chainTypes": chain_types,
        "attackPaths": paths,
    }
