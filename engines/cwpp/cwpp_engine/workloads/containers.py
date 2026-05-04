"""
CWPP Containers workload — K8s / EKS / ECS / AKS / GKE / ACK / GKE / OKE.

Pulls from the container-security engine ui-data and filters to the workload-specific
security domains:
  cluster_security  — control plane config, RBAC, admission controllers
  workload_security — pod security policies, resource limits, hostPath mounts
  rbac_access       — over-privileged service accounts, cluster-admin bindings
  runtime_audit     — privileged containers, host networking/PID, syscall policies

Image findings (image_security domain) are handled by the images.py workload module.
Serverless (lambda) findings are handled by serverless.py.

Source engine:
  container-security → GET /api/v1/container-security/ui-data

Service env var:
  CONTAINER_SEC_URL (default: http://engine-container-sec)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional

from ..core.http_client import get
from ..core.scorer import severity_to_score_penalty

logger = logging.getLogger("cwpp.workloads.containers")

CONTAINER_SEC_URL = os.getenv("CONTAINER_SEC_URL", "http://engine-container-sec")

# Domains owned by this workload module (image_security → images.py, lambda → serverless.py)
CONTAINER_DOMAINS = {"cluster_security", "workload_security", "rbac_access", "runtime_audit", "network_security"}


async def fetch(scan_run_id: str, tenant_id: str, auth_header: Optional[str] = None) -> Dict[str, Any]:
    """Fetch container/K8s workload data from the container-security engine."""
    data = await get(
        f"{CONTAINER_SEC_URL}/api/v1/container-security/ui-data",
        # container-security engine uses scan_id (not scan_run_id)
        params={"tenant_id": tenant_id, "scan_id": scan_run_id},
        auth_header=auth_header,
    )

    if data is None:
        return _unavailable()

    summary = data.get("summary", {})

    # Filter findings to container-specific domains only
    all_findings = data.get("findings", [])
    container_findings = [
        f for f in all_findings
        if f.get("security_domain") in CONTAINER_DOMAINS
        and f.get("container_service") not in ("lambda", "ecr")
    ]

    # Domain breakdown filtered to container domains
    domain_breakdown = [
        d for d in data.get("domain_breakdown", [])
        if d.get("security_domain") in CONTAINER_DOMAINS
    ]

    # Service breakdown — exclude lambda and ecr (they're in other workload modules)
    service_breakdown = [
        s for s in data.get("service_breakdown", [])
        if s.get("container_service") not in ("lambda", "ecr")
    ]

    # Clusters from inventory
    inventory = data.get("inventory", [])
    clusters = [i for i in inventory if i.get("resource_type") == "cluster"]
    workloads = [
        i for i in inventory
        if i.get("resource_type") not in ("cluster",)
        and i.get("container_service") not in ("lambda", "ecr")
    ]

    # Posture score: use sub-scores from container-security engine
    container_posture = _compute_container_score(summary)

    return {
        "workload_type": "containers",
        "status": "ok",
        "posture_score": container_posture,
        "summary": {
            "total_clusters": summary.get("total_clusters", 0),
            "total_workloads": summary.get("total_workloads", 0),
            "public_clusters": summary.get("public_clusters", 0),
            "cluster_security_score": summary.get("cluster_security_score", 0),
            "workload_security_score": summary.get("workload_security_score", 0),
            "rbac_access_score": summary.get("rbac_access_score", 0),
            "runtime_audit_score": summary.get("runtime_audit_score", 0),
            "network_exposure_score": summary.get("network_exposure_score", 0),
            "critical_findings": sum(f.get("severity", "").upper() == "CRITICAL" for f in container_findings),
            "high_findings": sum(f.get("severity", "").upper() == "HIGH" for f in container_findings),
            "total_findings": len(container_findings),
        },
        "data": {
            "clusters": clusters,
            "workloads": workloads,
            "domain_breakdown": domain_breakdown,
            "service_breakdown": service_breakdown,
            "findings": container_findings,
            "scan_trend": data.get("scan_trend", []),
            "scan_run_id": data.get("scan_id"),
        },
    }


def _compute_container_score(summary: Dict) -> Optional[float]:
    """Average the relevant sub-domain scores from container-security engine."""
    scores = []
    for key in ("cluster_security_score", "workload_security_score", "rbac_access_score", "runtime_audit_score"):
        v = summary.get(key)
        # Use explicit None check — v=0 is valid (terrible security), not falsy skip
        if v is not None:
            scores.append(float(v))
    if scores:
        return round(sum(scores) / len(scores), 1)
    # Fall back to overall posture score
    overall = summary.get("posture_score")
    return round(float(overall), 1) if overall is not None else None


def _unavailable() -> Dict[str, Any]:
    return {
        "workload_type": "containers",
        "status": "unavailable",
        "posture_score": None,
        "summary": {},
        "data": {},
    }
