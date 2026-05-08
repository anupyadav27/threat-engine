"""
Threat Detection pillar — MITRE ATT&CK mapping, attack chains, risk scoring.

Source:
  - Threat engine : threat findings, attack paths, MITRE techniques, risk scores

Service env var:
  THREAT_ENGINE_URL (default: http://engine-threat)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..core.http_client import get

logger = logging.getLogger("cnapp.pillars.threat")

THREAT_URL = os.getenv("THREAT_ENGINE_URL", "http://engine-threat")


async def fetch(scan_run_id: Optional[str], tenant_id: str, auth_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    params: Dict[str, Any] = {"tenant_id": tenant_id}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id

    data = await get(
        f"{THREAT_URL}/api/v1/threat/ui-data",
        params=params,
        timeout=30.0,
        headers=auth_headers,
    )

    if data is None:
        return _unavailable()

    posture_score = _derive_score(data)

    total_threats = int(data.get("total_threats", data.get("total_findings", 0)) or 0)
    if posture_score == 0 and total_threats == 0:
        return {
            "pillar": "threat",
            "status": "no_data",
            "posture_score": None,
            "reason": "no_findings_for_scan",
            "summary": {},
            "data": data,
        }

    return {
        "pillar": "threat",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "total_threats": total_threats,
            "critical": data.get("critical", 0),
            "high": data.get("high", 0),
            "medium": data.get("medium", 0),
            "low": data.get("low", 0),
            "attack_paths": data.get("attack_paths", 0),
            "mitre_techniques": data.get("mitre_techniques", []),
            "top_risk_score": data.get("top_risk_score", None),
        },
        "data": data,
    }


def _derive_score(data: Dict) -> Optional[float]:
    score = data.get("posture_score") or data.get("security_score")
    if score is not None:
        return round(float(score), 1)

    critical = int(data.get("critical", 0))
    high = int(data.get("high", 0))
    total = int(data.get("total_threats", data.get("total_findings", 0)))
    if total == 0:
        return 100.0
    penalty = min(critical * 5 + high * 2, 80)
    return round(max(100 - penalty, 20), 1)


def _unavailable() -> Dict[str, Any]:
    return {
        "pillar": "threat",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
