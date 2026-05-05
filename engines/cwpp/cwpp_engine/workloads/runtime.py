"""
CWPP Runtime workload — runtime threat signals.

Covers runtime security signals that don't fit cleanly into the other workload
types:
  - Privileged containers / host networking / hostPID
  - Syscall policy violations (seccomp/AppArmor not applied)
  - CIEM-sourced container runtime events (suspicious kubectl exec, API calls)
  - Attack surface findings from the container-security engine

Source engines:
  container-security → GET /api/v1/container-security/ui-data
  ciem              → GET /api/v1/ciem/findings?action_category=runtime

Service env vars:
  CONTAINER_SEC_URL (default: http://engine-container-sec)
  CIEM_ENGINE_URL   (default: http://engine-ciem/api/v1)
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

from ..core.http_client import CIEM_ENGINE_URL, get
from ..core.scorer import severity_to_score_penalty

logger = logging.getLogger("cwpp.workloads.runtime")

CONTAINER_SEC_URL = os.getenv("CONTAINER_SEC_URL", "http://engine-container-sec")

RUNTIME_DOMAINS = {"runtime_audit"}
RUNTIME_KEYWORDS = {"privileged", "host_network", "hostpid", "hostpath", "seccomp", "apparmor", "syscall"}


async def fetch(scan_run_id: str, tenant_id: str, auth_header: Optional[str] = None) -> Dict[str, Any]:
    """Fetch runtime threat signals from container-security and CIEM engines in parallel."""
    container_task = get(
        f"{CONTAINER_SEC_URL}/api/v1/container-security/ui-data",
        # container-security engine uses scan_id (not scan_run_id)
        params={"tenant_id": tenant_id, "scan_id": scan_run_id},
        auth_header=auth_header,
    )
    ciem_task = _fetch_ciem_runtime_events(scan_run_id, auth_header)

    container_result, ciem_result = await asyncio.gather(
        container_task, ciem_task, return_exceptions=True
    )

    data = container_result if not isinstance(container_result, Exception) else None
    ciem_runtime_events = (
        ciem_result if not isinstance(ciem_result, Exception)
        else _empty_ciem()
    )

    if data is None:
        unavail = _unavailable()
        unavail["ciem_runtime_events"] = ciem_runtime_events
        return unavail

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

    # Derive per-finding security flags from rule_id / title keywords
    privileged_containers = []
    for f in combined:
        is_priv = _is_privileged(f)
        is_hnet = _is_host_network(f)
        is_hpid = _is_host_pid(f)
        if is_priv or is_hnet or is_hpid:
            fd = f.get("finding_data") or {}
            privileged_containers.append({
                "resource_uid":   f.get("resource_uid"),
                "container_name": fd.get("container_name", f.get("resource_name", "")),
                "namespace":      fd.get("namespace", ""),
                "cluster_name":   f.get("cluster_name", ""),
                "privileged":     is_priv,
                "host_network":   is_hnet,
                "host_pid":       is_hpid,
                "seccomp_status": "unknown",   # not derivable from rule_id alone
                "severity":       f.get("severity"),
                "rule_id":        f.get("rule_id"),
            })

    privileged_count = sum(1 for f in combined if _is_privileged(f))
    host_network_count = sum(1 for f in combined if _is_host_network(f))

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
            "privileged_containers": privileged_containers,
        },
        "ciem_runtime_events": ciem_runtime_events,
    }


def _is_privileged(f: Dict[str, Any]) -> bool:
    """Return True if the finding indicates a privileged container."""
    return "privileged" in (f.get("rule_id", "") + f.get("title", "")).lower()


def _is_host_network(f: Dict[str, Any]) -> bool:
    """Return True if the finding indicates host network usage."""
    return "hostnetwork" in (f.get("rule_id", "") + f.get("title", "")).lower()


def _is_host_pid(f: Dict[str, Any]) -> bool:
    """Return True if the finding indicates host PID namespace usage."""
    return "hostpid" in (f.get("rule_id", "") + f.get("title", "")).lower()


async def _fetch_ciem_runtime_events(
    scan_run_id: str, auth_header: Optional[str]
) -> Dict[str, Any]:
    """Fetch CIEM behavioral events with action_category=runtime.

    Hard 5-second timeout so CWPP is never blocked by CIEM slowness.
    Returns _empty_ciem() on any failure.
    """
    try:
        resp = await get(
            f"{CIEM_ENGINE_URL}/ciem/findings",
            params={
                "action_category": "runtime",
                "scan_run_id": scan_run_id,
                "limit": 10,
            },
            timeout=5.0,
            auth_header=auth_header,
        )
        if resp is None:
            return _empty_ciem()

        findings = resp.get("findings", [])
        total = resp.get("total", len(findings))
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = (f.get("severity") or "low").lower()
            if sev in counts:
                counts[sev] += 1

        return {
            "count": total,
            **counts,
            "link_available": True,
            "sample_findings": [
                {
                    "title": f.get("title", ""),
                    "severity": f.get("severity"),
                    "actor_principal": f.get("actor_principal", ""),
                    "event_time": f.get("event_time", ""),
                }
                for f in findings[:3]
            ],
        }
    except Exception as exc:
        logger.warning("CIEM runtime events fetch failed: %s", exc)
        return _empty_ciem()


def _empty_ciem() -> Dict[str, Any]:
    """Return a zero-count CIEM block with link_available=False."""
    return {
        "count": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "link_available": False,
        "sample_findings": [],
    }


def _unavailable() -> Dict[str, Any]:
    return {
        "workload_type": "runtime",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
