"""
DSPM pillar — Data Security Posture Management.

Source:
  - DataSec engine : data store classification, encryption checks, PII/PHI exposure

Service env var:
  DATASEC_ENGINE_URL (default: http://engine-datasec)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..core.http_client import get

logger = logging.getLogger("cnapp.pillars.dspm")

DATASEC_URL = os.getenv("DATASEC_ENGINE_URL", "http://engine-datasec")


async def fetch(scan_run_id: str, tenant_id: str) -> Dict[str, Any]:
    params = {"scan_run_id": scan_run_id, "tenant_id": tenant_id}

    data = await get(f"{DATASEC_URL}/api/v1/data-security/ui-data", params=params)

    if data is None:
        return _unavailable()

    # datasec ui-data: score is in summary.data_risk_score
    # Use explicit None checks — data_risk_score = 0 is valid (no risk = perfect)
    summary = data.get("summary") or {}
    data_risk = summary.get("data_risk_score")
    if data_risk is not None:
        # data_risk_score is 0-100 risk scale; 0 = no risk = posture 100
        posture_score = round(max(0.0, 100.0 - float(data_risk)), 1) if data_risk > 0 else 100.0
    elif data.get("posture_score") is not None:
        posture_score = round(float(data["posture_score"]), 1)
    elif data.get("overall_score") is not None:
        posture_score = round(float(data["overall_score"]), 1)
    else:
        posture_score = None
    # posture_score already rounded above

    # Distinguish genuine score=0 (terrible security) from no-data (engine up but empty result)
    total_findings = int(data.get("total_findings", 0) or summary.get("total_findings", 0) or 0)
    total_resources = int(
        summary.get("total_data_stores", 0)
        or data.get("total_resources", 0)
        or data.get("total_stores", 0)
        or 0
    )
    if posture_score == 0 and total_findings == 0 and total_resources == 0:
        return {
            "pillar": "dspm",
            "status": "no_data",
            "posture_score": None,
            "reason": "no_findings_for_scan",
            "summary": {},
            "data": data,
        }

    return {
        "pillar": "dspm",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "sensitive_stores": summary.get("sensitive_exposed", data.get("sensitive_stores", 0)),
            "unencrypted_stores": summary.get("encrypted_pct", data.get("unencrypted_stores", 0)),
            "publicly_accessible": summary.get("public_data_stores", data.get("publicly_accessible", 0)),
            "pii_exposed": data.get("pii_exposed", 0),
            "phi_exposed": data.get("phi_exposed", 0),
            "total_findings": total_findings,
        },
        "data": data,
    }


def _unavailable() -> Dict[str, Any]:
    return {
        "pillar": "dspm",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
