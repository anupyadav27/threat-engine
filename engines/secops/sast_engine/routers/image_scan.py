"""
Image Scan Router — PLACEHOLDER.

Container image scanning is not yet implemented. This endpoint documents
the planned API contract so the CNAPP CWPP pillar and frontend can reference
a stable endpoint URL today.

Planned integration: Trivy or Grype as the underlying scanner, triggered
per-image ARN/digest pulled from ECR/ACR/GCR/OCIR discovery findings.

Endpoint:
  POST /api/v1/secops/image-scan       — Submit image for scanning (501 stub)
  GET  /api/v1/secops/image-scan/schema — Returns the planned request/response schema
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

router = APIRouter(tags=["Image Scan (Placeholder)"])


# ── Request / Response models (documents the planned API contract) ─────────────

class ImageScanRequest(BaseModel):
    image_uri: str = Field(
        ...,
        description="Full image URI including tag or digest. e.g. 123456789.dkr.ecr.ap-south-1.amazonaws.com/myapp:v1.2",
    )
    registry_type: str = Field(
        ...,
        description="Registry type: ecr | acr | gcr | ocir | dockerhub | quay",
    )
    scan_run_id: Optional[str] = Field(None, description="Associated CSPM scan_run_id")
    tenant_id: Optional[str] = Field(default="default-tenant")
    severity_threshold: Optional[str] = Field(
        default="HIGH",
        description="Minimum severity to report: CRITICAL | HIGH | MEDIUM | LOW",
    )


class VulnerabilityResult(BaseModel):
    cve_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    package: str
    installed_version: str
    fixed_version: Optional[str]
    cvss_score: Optional[float]
    description: str


class ImageScanResponse(BaseModel):
    scan_id: str
    image_uri: str
    status: str  # pending | scanning | completed | failed
    started_at: Optional[str]
    completed_at: Optional[str]
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    os_packages_scanned: int
    app_packages_scanned: int
    vulnerabilities: List[VulnerabilityResult]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/image-scan",
    status_code=501,
    summary="Scan a container image for vulnerabilities (PLACEHOLDER)",
    response_description="Not yet implemented",
)
async def submit_image_scan(request: ImageScanRequest) -> JSONResponse:
    """
    **PLACEHOLDER — not yet implemented.**

    When implemented, this endpoint will:
    1. Pull the image (or its manifest) from the specified registry
    2. Run Trivy/Grype against the image layers
    3. Enrich findings with CVE/EPSS/CISA-KEV data (same pipeline as SBOM engine)
    4. Persist results linked to the scan_run_id for CNAPP CWPP pillar aggregation
    5. Return a scan_id for async status polling

    Registry support planned: ECR, ACR, GCR, OCIR, Docker Hub, Quay.
    """
    return JSONResponse(
        status_code=501,
        content={
            "status": "not_implemented",
            "message": "Container image scanning is not yet implemented.",
            "planned_scanner": "Trivy / Grype",
            "planned_registries": ["ecr", "acr", "gcr", "ocir", "dockerhub", "quay"],
            "request_received": request.model_dump(),
            "schema_endpoint": "GET /api/v1/secops/image-scan/schema",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


@router.get(
    "/image-scan/schema",
    summary="Returns the planned image scan request/response schema",
)
async def image_scan_schema() -> Dict[str, Any]:
    """Returns the planned API contract for image scanning (for client integration prep)."""
    return {
        "status": "placeholder",
        "note": "Container image scanning is not yet implemented. Schema below documents the planned API.",
        "request_schema": ImageScanRequest.model_json_schema(),
        "response_schema": ImageScanResponse.model_json_schema(),
        "planned_integration": {
            "scanner": "Trivy or Grype",
            "trigger": "POST /api/v1/secops/image-scan",
            "status_poll": "GET /api/v1/secops/image-scan/{scan_id}/status",
            "results": "GET /api/v1/secops/image-scan/{scan_id}/results",
            "supported_registries": ["ecr", "acr", "gcr", "ocir", "dockerhub", "quay"],
            "output_format": "CycloneDX (same as SCA/SBOM engine)",
        },
        "cnapp_integration": {
            "pillar": "cwpp",
            "note": "Image scan results will be surfaced in CNAPP CWPP pillar via engine-cnapp aggregation",
        },
    }
