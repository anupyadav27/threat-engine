"""
Finding model — mirrors secops_findings table in threat_engine_secops DB.
"""

from typing import Optional, Any, Dict
from datetime import datetime
from pydantic import BaseModel


class SecOpsFinding(BaseModel):
    id: int
    secops_scan_id: str
    tenant_id: str
    customer_id: Optional[str] = None
    file_path: Optional[str] = None
    language: Optional[str] = None
    rule_id: Optional[str] = None
    severity: str
    message: Optional[str] = None
    line_number: Optional[int] = None
    status: Optional[str] = None
    resource: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None


class ScanReport(BaseModel):
    secops_scan_id: str
    orchestration_id: Optional[str] = None
    tenant_id: str
    customer_id: Optional[str] = None
    project_name: str
    repo_url: str
    branch: str = "main"
    status: str
    total_findings: int = 0
