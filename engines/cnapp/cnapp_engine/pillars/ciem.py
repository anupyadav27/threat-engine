"""
CIEM pillar — Cloud Identity & Entitlement Management.

Sources:
  - CIEM engine : log analysis, anomalies, overprivileged identities, attack paths
  - IAM engine  : IAM posture rules (57 rules), policy findings

Service env vars:
  CIEM_ENGINE_URL (default: http://engine-ciem)
  IAM_ENGINE_URL  (default: http://engine-iam)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..core.http_client import get

logger = logging.getLogger("cnapp.pillars.ciem")

CIEM_URL = os.getenv("CIEM_ENGINE_URL", "http://engine-ciem")
IAM_URL = os.getenv("IAM_ENGINE_URL", "http://engine-iam")


async def fetch(scan_run_id: str, tenant_id: str) -> Dict[str, Any]:
    # ciem/dashboard: tenant_id + scan_run_id
    ciem_data = await get(
        f"{CIEM_URL}/api/v1/ciem/dashboard",
        params={"tenant_id": tenant_id, "scan_run_id": scan_run_id},
    )
    # iam-security/ui-data: tenant_id + scan_id (not scan_run_id)
    iam_data = await get(
        f"{IAM_URL}/api/v1/iam-security/ui-data",
        params={"tenant_id": tenant_id, "scan_id": "latest"},
    )

    if ciem_data is None and iam_data is None:
        return _unavailable()

    posture_score = _derive_score(ciem_data, iam_data)

    # Distinguish genuine score=0 from empty scan result (engine up but no identity findings)
    ciem_summary = (ciem_data or {}).get("summary") or {}
    total_findings = int(
        ciem_summary.get("total_findings", 0)
        or _safe(iam_data, "total_findings", 0)
        or 0
    )
    if posture_score == 0 and total_findings == 0:
        return {
            "pillar": "ciem",
            "status": "no_data",
            "posture_score": None,
            "reason": "no_findings_for_scan",
            "summary": {},
            "data": {
                "ciem": ciem_data or {},
                "iam": iam_data or {},
            },
        }

    return {
        "pillar": "ciem",
        "status": "ok",
        "posture_score": posture_score,
        "summary": {
            "high_risk_identities": _safe(ciem_data, "high_risk_identities", 0),
            "anomalies_detected": _safe(ciem_data, "anomalies_detected", 0),
            "overprivileged_roles": _safe(ciem_data, "overprivileged_roles", 0),
            "iam_findings": _safe(iam_data, "total_findings", 0),
            "iam_risk_score": (iam_data or {}).get("summary", {}).get("risk_score"),
        },
        "data": {
            "ciem": ciem_data or {},
            "iam": iam_data or {},
        },
    }


def _derive_score(ciem_data: Optional[Dict], iam_data: Optional[Dict]) -> Optional[float]:
    scores = []
    if iam_data:
        # iam-security/ui-data: score is in summary.risk_score (risk scale → invert for posture)
        iam_summary = iam_data.get("summary") or {}
        risk = iam_summary.get("risk_score")
        s = iam_data.get("posture_score") or iam_data.get("pass_rate") or iam_data.get("overall_score")
        if risk is not None:
            scores.append(round(max(0.0, 100.0 - float(risk)), 1))
        elif s is not None:
            scores.append(float(s))

    if ciem_data:
        # ciem/dashboard returns {summary: {total_findings, ...}, by_severity: [...]}
        # No pre-computed score; derive from finding count + severity breakdown
        summary = ciem_data.get("summary") or {}
        total = int(summary.get("total_findings") or 0)
        by_sev = {item.get("severity", "").lower(): int(item.get("count", 0))
                  for item in (ciem_data.get("by_severity") or [])}
        critical = by_sev.get("critical", 0)
        high = by_sev.get("high", 0)
        if total == 0:
            scores.append(100.0)
        else:
            penalty = min(critical * 5 + high * 2, 80)
            scores.append(max(100.0 - penalty, 20.0))

    if not scores:
        return None
    return round(sum(scores) / len(scores), 1)


def _safe(data: Optional[Dict], key: str, default: Any) -> Any:
    if data is None:
        return default
    return data.get(key, default)


def _unavailable() -> Dict[str, Any]:
    return {
        "pillar": "ciem",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
