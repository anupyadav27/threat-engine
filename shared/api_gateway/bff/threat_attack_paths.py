"""BFF view: /threats/attack-paths page.

PostgreSQL-based — reads scored/classified attack paths from
threat_analysis.analysis_results JSONB. Orca-style card/table view.
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


@router.get("/threats/attack-paths")
async def view_threat_attack_paths(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    min_path_score: int = Query(0, ge=0, le=100),
):
    """BFF view for attack paths page — Orca-style.

    Reads scored/classified attack paths from threat_analysis JSONB.
    """

    params: Dict[str, str] = {"tenant_id": tenant_id, "limit": "500"}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id
    if min_path_score:
        params["min_path_score"] = str(min_path_score)

    results = await fetch_many([
        ("threat", "/api/v1/threat/analysis/attack-paths", params),
    ])

    raw = results[0]
    if not isinstance(raw, dict):
        raw = {}

    raw_paths = safe_get(raw, "attack_paths", [])
    if not isinstance(raw_paths, list):
        raw_paths = []

    summary = safe_get(raw, "summary", {})

    # Normalize paths for UI
    paths = [_normalize_path(p) for p in raw_paths if isinstance(p, dict)]

    # Deduplicate by id
    seen = set()
    unique = []
    for p in paths:
        if p["id"] not in seen:
            seen.add(p["id"])
            unique.append(p)
    paths = unique

    # KPIs
    total = len(paths)
    critical = sum(1 for p in paths if p["severity"] == "critical")
    high = sum(1 for p in paths if p["severity"] == "high")
    internet = sum(1 for p in paths if p.get("isInternetReachable"))

    # Chain type breakdown
    chain_types = safe_get(summary, "chain_types", {})

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
