"""
Findings router — fetch secops findings and manage false-positive suppression.

GET   /api/v1/secops-fix/findings/{secops_scan_id}
GET   /api/v1/secops-fix/findings/{secops_scan_id}/summary
PATCH /api/v1/secops-fix/findings/{secops_scan_id}/{finding_id}
        — mark a finding as false_positive or reopen it

False-positive workflow:
  1. SAST scanner runs → writes findings to secops_findings.
  2. Developer reviews via UI → identifies false positives.
  3. UI calls PATCH /findings/{scan_id}/{finding_id} with {"status": "false_positive"}.
  4. Next POST /remediate automatically skips those finding_ids.
  5. PATCH with {"status": "open"} reopens a suppressed finding.
"""

import logging
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from db.fetcher import get_findings, get_scan_report, get_finding_by_id
from db.writer import get_remediation_summary, mark_false_positive, mark_open

logger = logging.getLogger(__name__)
_audit  = logging.getLogger("audit.secops_fix")
router  = APIRouter()

_MAX_PAGE_SIZE    = 200
_DEFAULT_PAGE_SIZE = 50

_ALLOWED_PATCH_STATUSES = {"false_positive", "open"}


class FindingStatusUpdate(BaseModel):
    """Body for PATCH /findings/{scan_id}/{finding_id}."""
    status: str
    reason: Optional[str] = None   # optional free-text reason for audit log


@router.get("/{secops_scan_id}")
async def list_findings(
    secops_scan_id: str,
    severity: Optional[str] = Query(None, description="Comma-separated severities: critical,high,medium,low"),
    include_remediation: bool = Query(False, description="Include remediation status for each finding"),
    limit: int = Query(_DEFAULT_PAGE_SIZE, ge=1, le=_MAX_PAGE_SIZE, description=f"Page size (max {_MAX_PAGE_SIZE})"),
    offset: int = Query(0, ge=0, description="Number of findings to skip"),
):
    """
    Fetch findings for a scan with pagination, optionally filtered by severity.

    Example:
        GET /api/v1/secops-fix/findings/abc123?severity=critical,high&limit=50&offset=0
    """
    report = get_scan_report(secops_scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan not found: {secops_scan_id}")

    severity_filter: Optional[List[str]] = None
    if severity:
        severity_filter = [s.strip().lower() for s in severity.split(",") if s.strip()]

    all_findings = get_findings(secops_scan_id, severity_filter=severity_filter)
    total = len(all_findings)
    page = all_findings[offset: offset + limit]

    response = {
        "secops_scan_id": secops_scan_id,
        "project_name": report.project_name,
        "repo_url": report.repo_url,
        "branch": report.branch,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + limit) < total,
        "findings": [f.model_dump() for f in page],
    }

    if include_remediation:
        response["remediation_summary"] = get_remediation_summary(secops_scan_id)

    return response


@router.patch("/{secops_scan_id}/{finding_id}")
async def update_finding_status(
    secops_scan_id: str,
    finding_id: int,
    body: FindingStatusUpdate,
):
    """
    Mark a finding as a false positive or reopen it.

    - `status: "false_positive"` — suppresses the finding in future remediation runs.
    - `status: "open"`           — reopens a previously suppressed finding.

    The change takes effect immediately — the next POST /remediate will
    skip (or include) this finding accordingly.
    """
    if body.status not in _ALLOWED_PATCH_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of: {sorted(_ALLOWED_PATCH_STATUSES)}",
        )

    # Verify finding belongs to this scan
    finding = get_finding_by_id(finding_id)
    if not finding or finding.secops_scan_id != secops_scan_id:
        raise HTTPException(
            status_code=404,
            detail=f"Finding {finding_id} not found in scan {secops_scan_id}.",
        )

    if body.status == "false_positive":
        mark_false_positive(finding_id, suppressed_by=body.reason or "user")
        new_status = "false_positive"
    else:
        # Reopen: reset to 'pending' so next remediation run picks it up
        mark_open(finding_id)
        new_status = "open"

    _audit.info(
        "finding_status_updated",
        extra={
            "audit":           True,
            "event":           "finding_status_updated",
            "scan_id":         secops_scan_id,
            "finding_id":      finding_id,
            "new_status":      new_status,
            "reason":          body.reason,
        },
    )
    logger.info(
        f"[SecOpsFix] Finding {finding_id} set to '{new_status}' "
        f"(reason: {body.reason or 'none'})"
    )

    return {
        "finding_id":      finding_id,
        "secops_scan_id":  secops_scan_id,
        "status":          new_status,
        "message": (
            "Finding suppressed — it will be skipped in future remediation runs."
            if new_status == "false_positive"
            else "Finding reopened — it will be included in the next remediation run."
        ),
    }


@router.get("/{secops_scan_id}/summary")
async def findings_summary(secops_scan_id: str):
    """Severity breakdown + remediation status for a scan."""
    report = get_scan_report(secops_scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan not found: {secops_scan_id}")

    all_findings = get_findings(secops_scan_id)
    severity_counts: dict = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "secops_scan_id": secops_scan_id,
        "project_name": report.project_name,
        "total_findings": len(all_findings),
        "by_severity": severity_counts,
        "remediation": get_remediation_summary(secops_scan_id),
    }
