"""
CSPM pillar — Cloud Security Posture Management.

Sources:
  - Check engine  : compliance rule pass/fail findings
  - Compliance engine : framework-level scores (CIS, NIST, PCI-DSS, …)

Service env vars:
  CHECK_ENGINE_URL      (default: http://engine-check)
  COMPLIANCE_ENGINE_URL (default: http://engine-compliance)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..core.http_client import get

logger = logging.getLogger("cnapp.pillars.cspm")

CHECK_URL = os.getenv("CHECK_ENGINE_URL", "http://engine-check")
COMPLIANCE_URL = os.getenv("COMPLIANCE_ENGINE_URL", "http://engine-compliance")


async def fetch(scan_run_id: Optional[str], tenant_id: str, auth_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Fetch CSPM data from check + compliance engines."""
    params: Dict[str, Any] = {"tenant_id": tenant_id}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id

    check_data = await get(
        f"{CHECK_URL}/api/v1/check/findings/summary",
        params=params,
        headers=auth_headers,
    )
    compliance_data = await get(
        f"{COMPLIANCE_URL}/api/v1/compliance/frameworks",
        params={"tenant_id": tenant_id},
        timeout=10.0,
        headers=auth_headers,
    )

    if check_data is None and compliance_data is None:
        return _unavailable()

    posture_score = _derive_score(check_data, compliance_data)

    total_checks = int(
        _safe(check_data, "total_checks", _safe(check_data, "total", 0)) or 0
    )
    total_findings = int(_safe(check_data, "total_findings", 0) or 0)
    if posture_score == 0 and total_checks == 0 and total_findings == 0:
        return {
            "pillar": "cspm",
            "status": "no_data",
            "posture_score": None,
            "reason": "no_findings_for_scan",
            "summary": {},
            "data": {
                "check": check_data or {},
                "compliance": compliance_data or {},
            },
        }

    return {
        "pillar": "cspm",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "total_checks": total_checks,
            "passed": _safe(check_data, "passed", _safe(check_data, "pass_count", 0)),
            "failed": _safe(check_data, "failed", _safe(check_data, "fail_count", 0)),
            "pass_rate_pct": posture_score,
            "frameworks_evaluated": _safe(compliance_data, "frameworks", []),
        },
        "data": {
            "check": check_data or {},
            "compliance": compliance_data or {},
        },
    }


def _derive_score(check_data: Optional[Dict], compliance_data: Optional[Dict]) -> Optional[float]:
    if check_data:
        total = check_data.get("total") or check_data.get("total_checks") or 0
        if total == 0:
            return 100.0
        sc = check_data.get("status_counts") or {}
        passed = sc.get("PASS") or sc.get("pass") or check_data.get("passed") or check_data.get("pass_count") or 0
        if passed or total:
            return round(int(passed) / int(total) * 100, 1)
        rate = check_data.get("pass_rate") or check_data.get("pass_rate_pct")
        if rate is not None:
            return round(float(rate), 1)

    if compliance_data:
        score = compliance_data.get("overall_score") or compliance_data.get("posture_score")
        if score is not None:
            return round(float(score), 1)

    return None


def _safe(data: Optional[Dict], key: str, default: Any) -> Any:
    if data is None:
        return default
    return data.get(key, default)


def _unavailable() -> Dict[str, Any]:
    return {
        "pillar": "cspm",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
