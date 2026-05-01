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


async def fetch(scan_run_id: str, tenant_id: str) -> Dict[str, Any]:
    # threat/ui-data: tenant_id required, scan_run_id optional; 30s for large datasets
    data = await get(
        f"{THREAT_URL}/api/v1/threat/ui-data",
        params={"tenant_id": tenant_id, "scan_run_id": scan_run_id},
        timeout=30.0,
    )

    if data is None:
        return _unavailable()

    # Threat posture: inverse of risk — fewer high-severity findings → higher score
    posture_score = _derive_score(data)

    # Distinguish genuine score=0 from empty result (engine up but no threat findings)
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
    # If engine returns a posture/risk score directly, use it
    score = data.get("posture_score") or data.get("security_score")
    if score is not None:
        return round(float(score), 1)

    # Derive: penalise critical/high findings (simple heuristic)
    critical = int(data.get("critical", 0))
    high = int(data.get("high", 0))
    total = int(data.get("total_threats", data.get("total_findings", 0)))
    if total == 0:
        return 100.0  # no threats → perfect score
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
