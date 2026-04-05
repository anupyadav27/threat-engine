"""
Remediation request / response models.
"""

import re
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
_HTTPS_RE = re.compile(r'^https://', re.IGNORECASE)
_BRANCH_RE = re.compile(r'^[a-zA-Z0-9._/\-]{1,100}$')
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class RemediationRequest(BaseModel):
    secops_scan_id: str = Field(..., min_length=36, max_length=36)
    tenant_id: str = Field(..., min_length=1, max_length=128)
    repo_url: str = Field(..., min_length=10, max_length=500)
    repo_token: str = Field(..., min_length=1, max_length=256)
    source_branch: str = Field("main", min_length=1, max_length=100)
    orchestration_id: Optional[str] = Field(None, max_length=36)
    customer_id: Optional[str] = Field(None, max_length=128)
    severity_filter: Optional[List[str]] = None

    @field_validator("secops_scan_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        if not _UUID_RE.match(v):
            raise ValueError("secops_scan_id must be a valid UUID")
        return v.lower()

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        if not _HTTPS_RE.match(v):
            raise ValueError("repo_url must start with https://")
        return v

    @field_validator("source_branch")
    @classmethod
    def validate_branch(cls, v: str) -> str:
        if not _BRANCH_RE.match(v):
            raise ValueError("source_branch contains invalid characters")
        return v

    @field_validator("severity_filter")
    @classmethod
    def validate_severities(cls, v):
        if v is not None:
            invalid = [s for s in v if s.lower() not in _VALID_SEVERITIES]
            if invalid:
                raise ValueError(f"Invalid severities: {invalid}. Must be one of {_VALID_SEVERITIES}")
            return [s.lower() for s in v]
        return v


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
