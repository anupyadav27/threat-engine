"""
Remediation request / response models.
"""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class RemediationRequest(BaseModel):
    secops_scan_id: str
    tenant_id: str
    repo_url: str                        # GitHub repo to apply fixes to
    repo_token: str                      # GitHub PAT (write access)
    source_branch: str = "main"          # branch the scan was run on
    orchestration_id: Optional[str] = None
    customer_id: Optional[str] = None
    severity_filter: Optional[List[str]] = None   # e.g. ["critical","high"] — None = all


class RemediationStatus(BaseModel):
    remediation_id: str
    secops_scan_id: str
    finding_id: int
    rule_id: Optional[str]
    file_path: Optional[str]
    line_number: Optional[int]
    match_layer: Optional[str]           # exact / cwe / regex
    status: str                          # pending/matched/fix_generated/applied/failed/skipped
    fix_branch: Optional[str]
    pr_url: Optional[str]
    error_message: Optional[str]
    created_at: Optional[datetime]


class RemediationSummary(BaseModel):
    secops_scan_id: str
    total_findings: int
    matched: int
    fix_generated: int
    applied: int
    failed: int
    skipped: int
    fix_branch: Optional[str]
    pr_url: Optional[str]
    remediations: List[RemediationStatus]
