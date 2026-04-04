"""
Findings router — fetch secops findings from DB for a given scan.
GET /api/v1/secops-fix/findings/{secops_scan_id}
"""

import logging
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Query

from ..db.fetcher import get_findings, get_scan_report
from ..db.writer import get_remediation_summary

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/{secops_scan_id}")
async def list_findings(
    secops_scan_id: str,
    severity: Optional[str] = Query(None, description="Comma-separated severities: critical,high,medium,low"),
    include_remediation: bool = Query(False, description="Include remediation status for each finding"),
):
    """
    Fetch all findings for a scan, optionally filtered by severity.

    Example:
        GET /api/v1/secops-fix/findings/abc123?severity=critical,high
    """
    report = get_scan_report(secops_scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan not found: {secops_scan_id}")

    severity_filter: Optional[List[str]] = None
    if severity:
        severity_filter = [s.strip().lower() for s in severity.split(",") if s.strip()]

    findings = get_findings(secops_scan_id, severity_filter=severity_filter)

    response = {
        "secops_scan_id": secops_scan_id,
        "project_name": report.project_name,
        "repo_url": report.repo_url,
        "branch": report.branch,
        "total": len(findings),
        "findings": [f.model_dump() for f in findings],
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
    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "secops_scan_id": secops_scan_id,
        "project_name": report.project_name,
        "total_findings": len(all_findings),
        "by_severity": severity_counts,
        "remediation": get_remediation_summary(secops_scan_id),
    }
