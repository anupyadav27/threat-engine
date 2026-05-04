"""
CWPP Runtime workload — runtime threat signals.

Covers runtime security signals that don't fit cleanly into the other workload
types:
  - Privileged containers / host networking / hostPID
  - Syscall policy violations (seccomp/AppArmor not applied)
  - CIEM-sourced container runtime events (suspicious kubectl exec, API calls)
  - Attack surface findings from the container-security engine

Source engine:
  container-security → GET /api/v1/container-security/ui-data
  (filter: security_domain = 'runtime_audit', plus attack surface findings)

Service env var:
  CONTAINER_SEC_URL (default: http://engine-container-sec)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional

from ..core.http_client import get
from ..core.scorer import severity_to_score_penalty

logger = logging.getLogger("cwpp.workloads.runtime")

CONTAINER_SEC_URL = os.getenv("CONTAINER_SEC_URL", "http://engine-container-sec")

RUNTIME_DOMAINS = {"runtime_audit"}
RUNTIME_KEYWORDS = {"privileged", "host_network", "hostpid", "hostpath", "seccomp", "apparmor", "syscall"}


async def fetch(scan_run_id: str, tenant_id: str, auth_header: Optional[str] = None) -> Dict[str, Any]:
    """Fetch runtime threat signals from container-security engine."""
    data = await get(
        f"{CONTAINER_SEC_URL}/api/v1/container-security/ui-data",
        # container-security engine uses scan_id (not scan_run_id)
        params={"tenant_id": tenant_id, "scan_id": scan_run_id},
        auth_header=auth_header,
    )

    if data is None:
        return _unavailable()

    summary = data.get("summary", {})
    all_findings = data.get("findings", [])

    # Primary: runtime_audit domain findings
    runtime_findings = [
        f for f in all_findings
        if f.get("security_domain") in RUNTIME_DOMAINS
    ]

    # Secondary: findings with runtime-specific keywords in rule_id or title
    runtime_kw_findings = [
        f for f in all_findings
        if f not in runtime_findings
        and (
            any(kw in str(f.get("rule_id") or "").lower() for kw in RUNTIME_KEYWORDS)
            or any(kw in str(f.get("title") or "").lower() for kw in RUNTIME_KEYWORDS)
        )
    ]

    combined = runtime_findings + runtime_kw_findings
    critical = sum(1 for f in combined if f.get("severity", "").upper() == "CRITICAL")
    high = sum(1 for f in combined if f.get("severity", "").upper() == "HIGH")
    medium = sum(1 for f in combined if f.get("severity", "").upper() == "MEDIUM")
    total = len(combined)

    # Runtime posture: prefer runtime_audit_score from container engine
    # Use explicit None check — runtime_audit_score=0 is valid (terrible posture)
    runtime_posture = summary.get("runtime_audit_score")
    if runtime_posture is None:
        runtime_posture = severity_to_score_penalty(critical, high, medium, total)
    else:
        runtime_posture = round(float(runtime_posture), 1)

    # Count specific runtime risks
    privileged_count = sum(
        1 for f in combined
        if "privileged" in str(f.get("rule_id") or "").lower()
        or "privileged" in str(f.get("title") or "").lower()
    )
    host_network_count = sum(
        1 for f in combined
        if "host_network" in str(f.get("rule_id") or "").lower()
        or "hostnetwork" in str(f.get("title") or "").lower()
    )

    return {
        "workload_type": "runtime",
        "status": "ok",
        "posture_score": runtime_posture,
        "summary": {
            "runtime_audit_score": runtime_posture,
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "privileged_containers": privileged_count,
            "host_network_findings": host_network_count,
            "attack_surface_count": summary.get("attack_surface_count", 0),
        },
        "data": {
            "runtime_findings": runtime_findings,
            "runtime_keyword_findings": runtime_kw_findings,
        },
    }


def _unavailable() -> Dict[str, Any]:
    return {
        "workload_type": "runtime",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
