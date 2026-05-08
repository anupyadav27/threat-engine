"""
CWPP pillar — Cloud Workload Protection Platform.

Delegates entirely to the dedicated CWPP engine (engine-cwpp, port 8016)
which handles all workload-type aggregation internally.

Service env var:
  CWPP_ENGINE_URL (default: http://engine-cwpp)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..core.http_client import get

logger = logging.getLogger("cnapp.pillars.cwpp")

CWPP_URL = os.getenv("CWPP_ENGINE_URL", "http://engine-cwpp")


async def fetch(scan_run_id: Optional[str], tenant_id: str, auth_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Fetch CWPP data from the dedicated CWPP engine."""
    params: Dict[str, Any] = {"tenant_id": tenant_id}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id

    data = await get(
        f"{CWPP_URL}/api/v1/cwpp/ui-data",
        params=params,
        headers=auth_headers,
    )

    if data is None:
        return _unavailable()

    posture_score = data.get("cwpp_posture_score")
    if posture_score is not None:
        posture_score = round(float(posture_score), 1)

    workloads = data.get("workloads", {})

    total_findings = int(data.get("total_findings", 0) or 0)
    total_workload_types_available = len(data.get("workload_types_available") or [])
    if posture_score == 0 and total_findings == 0 and total_workload_types_available == 0:
        return {
            "pillar": "cwpp",
            "status": "no_data",
            "posture_score": None,
            "reason": "no_findings_for_scan",
            "summary": {},
            "data": data,
        }

    return {
        "pillar": "cwpp",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "total_findings": total_findings,
            "critical_findings": data.get("critical_findings", 0),
            "risk_band": data.get("risk_band", "unknown"),
            "workload_types_available": data.get("workload_types_available", []),
            "workload_types_unavailable": data.get("workload_types_unavailable", []),
            "workload_scores": {
                wtype: wdata.get("posture_score")
                for wtype, wdata in workloads.items()
            },
            "image_scan_status": (
                workloads.get("images", {})
                .get("summary", {})
                .get("image_scan_status", "not_implemented")
            ),
        },
        "data": data,
    }


def _unavailable() -> Dict[str, Any]:
    return {
        "pillar": "cwpp",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
