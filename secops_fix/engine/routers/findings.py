"""
Findings router — fetch secops findings from DB for a given scan.
GET /api/v1/secops-fix/findings/{secops_scan_id}
"""

import logging
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query

from db.fetcher import get_findings, get_scan_report
from db.writer import get_remediation_summary

logger = logging.getLogger(__name__)
router = APIRouter()

_MAX_PAGE_SIZE = 200
_DEFAULT_PAGE_SIZE = 50


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
