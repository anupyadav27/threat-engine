"""
Network Security pillar — 7-layer network posture analysis.

Source:
  - Network Security engine : VPC, SG, NACL, LB, WAF, flow logs analysis

Service env var:
  NETWORK_ENGINE_URL (default: http://engine-network)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..core.http_client import get

logger = logging.getLogger("cnapp.pillars.network")

NETWORK_URL = os.getenv("NETWORK_ENGINE_URL", "http://engine-network")


async def fetch(scan_run_id: Optional[str], tenant_id: str, auth_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    # network engine uses scan_id (not scan_run_id); 30s timeout for slow topology queries
    params: Dict[str, Any] = {"tenant_id": tenant_id}
    if scan_run_id:
        params["scan_id"] = scan_run_id

    data = await get(
        f"{NETWORK_URL}/api/v1/network-security/ui-data",
        params=params,
        timeout=30.0,
        headers=auth_headers,
    )

    if data is None:
        return _unavailable()

    summary = data.get("summary") or {}
    posture_score = (
        summary.get("pass_rate")
        or summary.get("posture_score")
        or data.get("posture_score")
        or data.get("network_posture_score")
        or data.get("overall_score")
    )
    if posture_score is not None:
        posture_score = round(float(posture_score), 1)

    total_findings = int(data.get("total_findings", 0) or 0)
    if posture_score == 0 and total_findings == 0:
        return {
            "pillar": "network",
            "status": "no_data",
            "posture_score": None,
            "reason": "no_findings_for_scan",
            "summary": {},
            "data": data,
        }

    return {
        "pillar": "network",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "internet_exposed_resources": summary.get("internet_exposed_resources", data.get("internet_exposed_resources", 0)),
            "open_sensitive_ports": summary.get("open_sensitive_ports", data.get("open_sensitive_ports", 0)),
            "resources_without_waf": summary.get("resources_without_waf", data.get("resources_without_waf", 0)),
            "resources_without_flow_logs": summary.get("resources_without_flow_logs", data.get("resources_without_flow_logs", 0)),
            "lateral_movement_paths": summary.get("lateral_movement_paths", data.get("lateral_movement_paths", 0)),
            "total_findings": total_findings,
            "layers_analyzed": summary.get("layers_analyzed", data.get("layers_analyzed", ["L1", "L2", "L3", "L4", "L5", "L6", "L7"])),
        },
        "data": data,
    }


def _unavailable() -> Dict[str, Any]:
    return {
        "pillar": "network",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
