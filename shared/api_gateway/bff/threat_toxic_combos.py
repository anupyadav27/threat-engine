"""BFF view: /threats/toxic-combinations page.

Retrieves toxic combinations and co-occurrence matrix from the threat
engine graph endpoints.
"""

from typing import Optional, List

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get
from ._transforms import _safe_lower

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/threats/toxic-combinations")
async def view_threat_toxic_combos(
    tenant_id: str = Query(...),
    min_threats: int = Query(2, ge=1),
):
    """BFF view for the toxic combinations page.

    Fans out to the toxic-combinations list and matrix endpoints in
    parallel and returns KPIs, the combination list, and the
    co-occurrence matrix.
    """

    results = await fetch_many([
        ("threat", "/api/v1/graph/toxic-combinations", {
            "tenant_id": tenant_id,
            "min_threats": str(min_threats),
        }),
        ("threat", "/api/v1/graph/toxic-combinations/matrix", {
            "tenant_id": tenant_id,
            "min_threats": str(min_threats),
        }),
    ])

    combos_data, matrix_data = results

    # Safely handle None
    if not isinstance(combos_data, (dict, list)):
        combos_data = {}
    if not isinstance(matrix_data, (dict, list)):
        matrix_data = {}

    # Extract combinations list
    if isinstance(combos_data, list):
        raw_combos = combos_data
    else:
        raw_combos = (
            safe_get(combos_data, "combinations", [])
            or safe_get(combos_data, "toxic_combinations", [])
            or safe_get(combos_data, "data", [])
        )
    if not isinstance(raw_combos, list):
        raw_combos = []

    # Normalize combinations
    combos: List[dict] = []
    for c in raw_combos:
        combos.append({
            "id": c.get("id") or c.get("combination_id", ""),
            "name": c.get("name") or c.get("combination_name", ""),
            "severity": _safe_lower(c.get("severity") or c.get("risk_level")),
            "threats": c.get("threats") or c.get("threat_ids", []),
            "threatCount": c.get("threat_count") or len(c.get("threats") or c.get("threat_ids") or []),
            "resourceUid": c.get("resource_uid") or c.get("resource_id", ""),
            "resourceType": c.get("resource_type", ""),
            "description": c.get("description", ""),
            "riskScore": c.get("risk_score", 0),
        })

    # KPIs
    total = len(combos)
    critical = sum(1 for c in combos if c.get("severity") == "critical")
    high = sum(1 for c in combos if c.get("severity") == "high")
    avg_threats = (
        round(sum(c.get("threatCount", 0) for c in combos) / total, 1)
        if total else 0
    )

    # Co-occurrence matrix
    if isinstance(matrix_data, list):
        matrix = matrix_data
    elif isinstance(matrix_data, dict):
        matrix = (
            safe_get(matrix_data, "matrix", None)
            or safe_get(matrix_data, "co_occurrence", None)
            or matrix_data
        )
    else:
        matrix = {}

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
