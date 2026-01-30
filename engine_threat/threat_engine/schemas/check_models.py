"""
Pydantic models for ConfigScan Check Results API
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class CheckStatus(str, Enum):
    """Check result status"""
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class ServiceStats(BaseModel):
    """Statistics for a single service"""
    service: str = Field(..., description="Service name (e.g., s3, iam, ec2)")
    total: int = Field(..., description="Total checks for this service")
    passed: int = Field(..., description="Number of passed checks")
    failed: int = Field(..., description="Number of failed checks")
    error: int = Field(default=0, description="Number of checks with errors")
    pass_rate: float = Field(..., description="Pass rate percentage (0-100)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "service": "s3",
                "total": 2112,
                "passed": 604,
                "failed": 1508,
                "error": 0,
                "pass_rate": 28.6
            }
        }


class ScanSummary(BaseModel):
    """Summary of a check scan"""
    scan_id: str = Field(..., description="Check scan identifier")
    discovery_scan_id: Optional[str] = Field(None, description="Associated discovery scan ID")
    customer_id: str
    tenant_id: str
    provider: str = Field(default="aws", description="Cloud provider")
    hierarchy_id: str = Field(..., description="Account/Project/Org ID")
    hierarchy_type: str = Field(default="account", description="Hierarchy type")
    total_checks: int = Field(..., description="Total checks executed")
    passed: int = Field(..., description="Checks that passed")
    failed: int = Field(..., description="Checks that failed")
    error: int = Field(default=0, description="Checks with errors")
    services_scanned: int = Field(..., description="Number of services scanned")
    scan_timestamp: datetime = Field(..., description="Scan execution time")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "check_20260122_210506",
                "discovery_scan_id": "discovery_20260122_080533",
                "customer_id": "test_customer",
                "tenant_id": "test_tenant",
                "provider": "aws",
                "hierarchy_id": "039612851381",
                "total_checks": 70988,
                "passed": 7836,
                "failed": 63152,
                "error": 0,
                "services_scanned": 100,
                "scan_timestamp": "2026-01-22T21:05:06Z"
            }
        }


class FindingDetail(BaseModel):
    """Detailed check finding"""
    id: Optional[int] = Field(None, description="Database ID (if from database)")
    scan_id: str = Field(..., description="Check scan identifier")
    discovery_scan_id: Optional[str] = Field(None, description="Discovery scan ID")
    customer_id: str
    tenant_id: str
    provider: str
    hierarchy_id: str
    hierarchy_type: str
    rule_id: str = Field(..., description="Rule identifier (e.g., aws.s3.bucket.versioning_enabled)")
    resource_arn: Optional[str] = Field(None, description="Resource ARN")
    resource_id: Optional[str] = Field(None, description="Resource ID")
    resource_type: str = Field(..., description="Service/resource type (e.g., s3, iam)")
    status: CheckStatus = Field(..., description="Check result status")
    checked_fields: List[str] = Field(default_factory=list, description="Fields that were evaluated")
    finding_data: Dict[str, Any] = Field(default_factory=dict, description="Additional finding context")
    scan_timestamp: datetime = Field(..., description="When check was executed")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "check_20260122_210506",
                "rule_id": "aws.s3.bucket.versioning_enabled",
                "resource_arn": "arn:aws:s3:::my-bucket",
                "resource_id": "my-bucket",
                "resource_type": "s3",
                "status": "FAIL",
                "checked_fields": ["Status"],
                "finding_data": {
                    "discovery_id": "aws.s3.get_bucket_versioning"
                }
            }
        }


class FindingList(BaseModel):
    """Paginated list of findings"""
    findings: List[FindingDetail] = Field(default_factory=list)
    total: int = Field(..., description="Total number of findings (before pagination)")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=50, description="Results per page")
    total_pages: int = Field(..., description="Total number of pages")
    
    class Config:
        json_schema_extra = {
            "example": {
                "findings": [],
                "total": 70988,
                "page": 1,
                "page_size": 50,
                "total_pages": 1420
            }
        }


class CheckDashboard(BaseModel):
    """Dashboard statistics for check scans"""
    total_checks: int = Field(..., description="Total checks across all scans")
    passed: int
    failed: int
    error: int = Field(default=0)
    pass_rate: float = Field(..., description="Overall pass rate percentage")
    services_scanned: int = Field(..., description="Unique services with checks")
    accounts_scanned: int = Field(default=1, description="Number of accounts scanned")
    top_failing_services: List[ServiceStats] = Field(
        default_factory=list,
        description="Services with most failures"
    )
    recent_scans: List[ScanSummary] = Field(
        default_factory=list,
        description="Recent check scans"
    )
    last_scan_timestamp: Optional[datetime] = Field(None, description="Most recent scan time")
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_checks": 70988,
                "passed": 7836,
                "failed": 63152,
                "error": 0,
                "pass_rate": 11.0,
                "services_scanned": 100,
                "top_failing_services": [],
                "recent_scans": []
            }
        }


class ServiceDetail(BaseModel):
    """Detailed statistics for a specific service"""
    service: str
    scan_id: str
    total_checks: int
    passed: int
    failed: int
    error: int = Field(default=0)
    pass_rate: float
    rules: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of rules with their statistics"
    )
    top_failing_rules: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Rules with most failures"
    )
    resources_affected: int = Field(..., description="Unique resources with findings")
    
    class Config:
        json_schema_extra = {
            "example": {
                "service": "s3",
                "scan_id": "check_20260122_210506",
                "total_checks": 2112,
                "passed": 604,
                "failed": 1508,
                "pass_rate": 28.6,
                "resources_affected": 96
            }
        }


class ResourceFindings(BaseModel):
    """All findings for a specific resource"""
    resource_arn: str
    resource_id: Optional[str]
    resource_type: str
    total_findings: int
    passed: int
    failed: int
    findings: List[FindingDetail]
    
    class Config:
        json_schema_extra = {
            "example": {
                "resource_arn": "arn:aws:s3:::my-bucket",
                "resource_id": "my-bucket",
                "resource_type": "s3",
                "total_findings": 22,
                "passed": 8,
                "failed": 14,
                "findings": []
            }
        }


class RuleFindings(BaseModel):
    """All findings for a specific rule"""
    rule_id: str
    total_findings: int
    passed: int
    failed: int
    error: int = Field(default=0)
    service: str
    findings: List[FindingDetail]
    resources_affected: List[str] = Field(
        default_factory=list,
        description="List of resource ARNs affected by this rule"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "rule_id": "aws.s3.bucket.versioning_enabled",
                "total_findings": 96,
                "passed": 24,
                "failed": 72,
                "service": "s3",
                "resources_affected": []
            }
        }


class ScanListItem(BaseModel):
    """Summary item for scan list"""
    scan_id: str
    discovery_scan_id: Optional[str]
    customer_id: str
    tenant_id: str
    provider: str
    hierarchy_id: str
    total_checks: int
    passed: int
    failed: int
    error: int = Field(default=0)
    pass_rate: float
    services_scanned: int
    scan_timestamp: datetime


class ScanList(BaseModel):
    """Paginated list of scans"""
    scans: List[ScanListItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class SearchRequest(BaseModel):
    """Search request for findings"""
    query: str = Field(..., min_length=1, description="Search query (ARN, rule ID, or service)")
    tenant_id: str
    customer_id: Optional[str] = None
    filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional filters (service, status, scan_id)"
    )
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=1000)


class ExportRequest(BaseModel):
    """Export request for scan results"""
    scan_id: str
    tenant_id: str
    customer_id: Optional[str] = None
    format: str = Field(default="json", description="Export format: json, csv, or pdf")
    filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Filters to apply before export"
    )
