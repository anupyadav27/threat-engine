"""
CWPP Images workload — Container image security / supply-chain risk.

Two sources:
  1. Container-security engine  — image_security domain findings (ECR/ACR/GCR/OCIR posture checks)
                                   e.g. scan-on-push disabled, unscanned images, image policy webhooks
  2. SecOps image-scan endpoint — actual CVE scan per image digest (PLACEHOLDER — 501 today)
                                   When implemented (Trivy/Grype), CVE findings will appear here.

Source engines:
  container-security → GET /api/v1/container-security/ui-data   (posture)
  secops             → POST /api/v1/secops/image-scan            (CVE scan — placeholder)
  secops             → GET  /api/v1/secops/image-scan/schema     (planned schema)

Service env vars:
  CONTAINER_SEC_URL (default: http://engine-container-sec)
  SECOPS_ENGINE_URL (default: http://engine-secops)
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional

from ..core.http_client import get
from ..core.scorer import severity_to_score_penalty

logger = logging.getLogger("cwpp.workloads.images")

CONTAINER_SEC_URL = os.getenv("CONTAINER_SEC_URL", "http://engine-container-sec")
SECOPS_URL = os.getenv("SECOPS_ENGINE_URL", "http://engine-secops")

IMAGE_DOMAIN = "image_security"
IMAGE_SERVICE = "ecr"  # catches ecr / acr / gcr / ocir (all registry discoveries map here)


async def fetch(scan_run_id: Optional[str], tenant_id: str, auth_header: Optional[str] = None) -> Dict[str, Any]:
    """Fetch image workload data from container-security + secops image-scan."""

    # 1. Posture checks from container-security engine
    img_params: Dict[str, Any] = {"tenant_id": tenant_id}
    if scan_run_id:
        img_params["scan_id"] = scan_run_id  # container-security uses scan_id
    container_data = await get(
        f"{CONTAINER_SEC_URL}/api/v1/container-security/ui-data",
        params=img_params,
        auth_header=auth_header,
    )

    # 2. Image scan schema (to show planned capability even when 501)
    image_scan_schema = await get(f"{SECOPS_URL}/api/v1/secops/image-scan/schema", auth_header=auth_header)

    # Derive posture findings even if container_data is missing
    if container_data is None:
        return _unavailable(image_scan_schema)

    summary = container_data.get("summary", {})
    all_findings = container_data.get("findings", [])
    inventory = container_data.get("inventory", [])

    # Filter to image-specific findings
    image_findings = [
        f for f in all_findings
        if f.get("security_domain") == IMAGE_DOMAIN
        or f.get("container_service") in ("ecr", "acr", "gcr", "ocir", "artifact_registry")
    ]

    # Images from inventory
    image_inventory = [
        i for i in inventory
        if i.get("container_service") in ("ecr", "acr", "gcr", "ocir", "artifact_registry")
        or i.get("resource_type") in ("container_image", "image", "repository")
    ]

    critical = sum(1 for f in image_findings if f.get("severity", "").upper() == "CRITICAL")
    high = sum(1 for f in image_findings if f.get("severity", "").upper() == "HIGH")
    total = len(image_findings)

    # Posture score: prefer sub-score from container engine, fall back to severity heuristic
    # Use explicit None check — image_security_score=0 is valid (terrible posture)
    image_posture = summary.get("image_security_score")
    if image_posture is None:
        image_posture = severity_to_score_penalty(critical, high, 0, total)
    else:
        image_posture = round(float(image_posture), 1)

    return {
        "workload_type": "images",
        "status": "ok",
        "posture_score": image_posture,
        "summary": {
            "total_images": summary.get("total_images", len(image_inventory)),
            "image_security_score": image_posture,
            "critical_findings": critical,
            "high_findings": high,
            "total_findings": total,
            "image_scan_status": "not_implemented",
            "image_scan_note": (
                "CVE scanning per image digest is not yet implemented. "
                "Current findings are posture checks (scan-on-push policy, "
                "unscanned image age, image policy webhooks). "
                "Trivy/Grype integration is planned via POST /api/v1/secops/image-scan."
            ),
        },
        "data": {
            "image_inventory": image_inventory,
            "posture_findings": image_findings,
            "cve_scan": {
                "status": "not_implemented",
                "planned_endpoint": "POST /api/v1/secops/image-scan",
                "schema": image_scan_schema or {},
                "note": "Container image CVE scanning (Trivy/Grype) is planned. Backend implementation pending.",
            },
        },
    }


def _unavailable(image_scan_schema: Optional[Dict]) -> Dict[str, Any]:
    return {
        "workload_type": "images",
        "status": "unavailable",
        "posture_score": None,
        "summary": {
            "image_scan_status": "not_implemented",
        },
        "data": {
            "cve_scan": {
                "status": "not_implemented",
                "planned_endpoint": "POST /api/v1/secops/image-scan",
                "schema": image_scan_schema or {},
            },
        },
    }
