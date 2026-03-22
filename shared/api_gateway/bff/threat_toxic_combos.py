"""BFF view: /threats/toxic-combinations page.

PostgreSQL-based — groups threat_detections by resource_uid to find
resources with multiple overlapping threats. Orca-style view.
"""

from collections import defaultdict
from typing import Dict, List, Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _build_cooccurrence_matrix(combos: List[dict]) -> dict:
    """Build a MITRE technique co-occurrence matrix from combinations.

    Counts how often pairs of techniques appear together on the same
    resource, producing a heatmap-ready data structure.
    """
    pair_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    all_categories: set = set()

    for c in combos:
        techniques = c.get("mitreTechniques") or c.get("mitre_techniques") or []
        all_categories.update(techniques)

        for i, a in enumerate(techniques):
            for b in techniques[i:]:
                pair_counts[a][b] += 1
                if a != b:
                    pair_counts[b][a] += 1

    categories = sorted(all_categories)
    data: Dict[str, Dict[str, int]] = {}
    for cat in categories:
        data[cat] = {c: pair_counts.get(cat, {}).get(c, 0) for c in categories}

    return {"categories": categories, "data": data}


@router.get("/threats/toxic-combinations")
async def view_threat_toxic_combos(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    min_threats: int = Query(2, ge=2),
):
    """BFF view for the toxic combinations page — Orca-style.

    Reads from PostgreSQL: groups threat_detections by resource_uid
    to find resources with 2+ overlapping threats.
    """

    params: Dict[str, str] = {
        "tenant_id": tenant_id,
        "min_threats": str(min_threats),
        "limit": "500",
    }
    if scan_run_id:
        params["scan_run_id"] = scan_run_id

    results = await fetch_many([
        ("threat", "/api/v1/threat/analysis/toxic-combinations", params),
    ])

    raw = results[0]
    if not isinstance(raw, dict):
        raw = {}

    raw_combos = safe_get(raw, "toxic_combinations", [])
    if not isinstance(raw_combos, list):
        raw_combos = []
    summary = safe_get(raw, "summary", {})

    # Normalize for UI
    combos: List[dict] = []
    for c in raw_combos:
        severities = c.get("severities") or []
        # Worst severity
        combo_severity = c.get("combo_severity", "low")

        combos.append({
            "id": c.get("resource_uid", ""),
            "resourceUid": c.get("resource_uid", ""),
            "resourceName": c.get("resource_name", ""),
            "resourceType": c.get("resource_type", ""),
            "provider": (c.get("provider") or "").upper() or "--",
            "accountId": c.get("account_id", ""),
            "region": c.get("region", ""),
            "severity": combo_severity,
            "threatCount": c.get("threat_count", 0),
            "maxRiskScore": c.get("max_risk_score", 0),
            "toxicityScore": c.get("toxicity_score", 0),
            "detectionIds": c.get("detection_ids", []),
            "severities": severities,
            "ruleNames": c.get("rule_names") or [],
            "categories": c.get("categories") or [],
            "mitreTechniques": c.get("mitre_techniques") or [],
        })

    # KPIs
    total = len(combos)
    severity_counts = safe_get(summary, "severity_counts", {})
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    avg_threats = safe_get(summary, "avg_threats_per_resource", 0)

    # Build co-occurrence matrix from MITRE techniques
    matrix = _build_cooccurrence_matrix(combos)

    return {
        "kpi": {
            "total": total,
            "critical": critical,
            "high": high,
            "avgThreatsPerCombo": avg_threats,
        },
        "toxicCombinations": combos,
        "coOccurrenceMatrix": matrix,
    }
