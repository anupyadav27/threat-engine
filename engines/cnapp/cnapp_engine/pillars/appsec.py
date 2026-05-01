"""
AppSec pillar — Application Security (Code Security).

CNAPP's AppSec pillar covers shift-left security:
  - SAST : static code analysis (14 languages, ~2,900 rules)
  - DAST : runtime web application testing (OWASP Top 10)
  - SCA  : software composition analysis / SBOM / dependency CVEs
  - Image scan : container image scanning (placeholder — not yet implemented)

Source:
  - SecOps engine : SAST + DAST + SCA (unified code security)

Service env var:
  SECOPS_ENGINE_URL (default: http://engine-secops)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..core.http_client import get

logger = logging.getLogger("cnapp.pillars.appsec")

SECOPS_URL = os.getenv("SECOPS_ENGINE_URL", "http://engine-secops")


async def fetch(scan_run_id: str, tenant_id: str) -> Dict[str, Any]:
    params = {"scan_run_id": scan_run_id, "tenant_id": tenant_id, "limit": 50}

    # Fetch recent SAST scans
    sast_data = await get(f"{SECOPS_URL}/api/v1/secops/sast/scans", params=params)

    # Fetch recent DAST scans (use scan_run_id as filter if engine supports it)
    dast_params = {"limit": 20}
    dast_data = await get(f"{SECOPS_URL}/api/v1/secops/dast/scans", params=dast_params)

    # Image scanning — placeholder
    image_scan = {
        "status": "not_implemented",
        "note": "Container image scanning is planned. Endpoint: POST /api/v1/secops/image-scan",
    }

    if sast_data is None and dast_data is None:
        result = _unavailable()
        result["data"]["image_scan"] = image_scan
        return result

    posture_score = _derive_score(sast_data, dast_data)

    # Normalise sast_data — could be a list of scans or a dict summary
    sast_summary = _extract_sast_summary(sast_data)
    dast_summary = _extract_dast_summary(dast_data)

    # Distinguish genuine score=0 from empty result (engine up but no scans submitted)
    total_scans = int(sast_summary.get("count", 0) or 0) + int(dast_summary.get("count", 0) or 0)
    total_critical = int(sast_summary.get("critical", 0) or 0) + int(dast_summary.get("critical", 0) or 0)
    total_high = int(sast_summary.get("high", 0) or 0) + int(dast_summary.get("high", 0) or 0)
    if posture_score == 0 and total_scans == 0 and total_critical == 0 and total_high == 0:
        return {
            "pillar": "appsec",
            "status": "no_data",
            "posture_score": None,
            "reason": "no_findings_for_scan",
            "summary": {},
            "data": {
                "sast": sast_data or {},
                "dast": dast_data or {},
                "sca": {"note": "SCA/SBOM available at /api/v1/secops/sca/ on SecOps engine"},
                "image_scan": image_scan,
            },
        }

    return {
        "pillar": "appsec",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "sast_scans": sast_summary.get("count", 0),
            "sast_findings_critical": sast_summary.get("critical", 0),
            "sast_findings_high": sast_summary.get("high", 0),
            "dast_scans": dast_summary.get("count", 0),
            "dast_findings_critical": dast_summary.get("critical", 0),
            "image_scan_status": "not_implemented",
        },
        "data": {
            "sast": sast_data or {},
            "dast": dast_data or {},
            "sca": {"note": "SCA/SBOM available at /api/v1/secops/sca/ on SecOps engine"},
            "image_scan": image_scan,
        },
    }


def _extract_sast_summary(data: Optional[Any]) -> Dict:
    if data is None:
        return {}
    if isinstance(data, list):
        return {
            "count": len(data),
            "critical": sum(s.get("critical_count", s.get("critical", 0)) for s in data),
            "high": sum(s.get("high_count", s.get("high", 0)) for s in data),
        }
    if isinstance(data, dict):
        return {
            "count": data.get("total", data.get("count", 0)),
            "critical": data.get("critical", 0),
            "high": data.get("high", 0),
        }
    return {}


def _extract_dast_summary(data: Optional[Any]) -> Dict:
    return _extract_sast_summary(data)  # same shape


def _derive_score(sast_data: Optional[Any], dast_data: Optional[Any]) -> Optional[float]:
    sast_summary = _extract_sast_summary(sast_data)
    dast_summary = _extract_dast_summary(dast_data)

    critical = sast_summary.get("critical", 0) + dast_summary.get("critical", 0)
    high = sast_summary.get("high", 0) + dast_summary.get("high", 0)
    penalty = min(critical * 5 + high * 2, 80)
    return round(max(100 - penalty, 20), 1)


def _unavailable() -> Dict[str, Any]:
    return {
        "pillar": "appsec",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
