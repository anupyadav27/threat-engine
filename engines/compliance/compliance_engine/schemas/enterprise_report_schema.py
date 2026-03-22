"""
Enterprise-Grade Compliance Report Schema (cspm_misconfig_report.v1)

This module defines the enterprise-grade report structure with:
- Tenant and scan context
- Detailed findings with evidence references
- Framework controls with finding references
- Asset snapshots
- Posture summary with per-control counts
"""

from typing import Dict, List, Any, Optional, Literal
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class TriggerType(str, Enum):
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    API = "api"
    WEBHOOK = "webhook"


class Cloud(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALICLOUD = "alicloud"
    OCI = "oci"
    IBM = "ibm"


class CollectionMode(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"


class ControlStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    EXCEPTION = "exception"


class EvidenceType(str, Enum):
    CONFIG = "config"
    API_RESPONSE = "api_response"
    LOG = "log"
    SCREENSHOT = "screenshot"
    NETWORK_TRACE = "network_trace"


# Schema Models

class Tenant(BaseModel):
    """Tenant information."""
    tenant_id: str = Field(..., description="Unique tenant identifier")
    tenant_name: Optional[str] = Field(None, description="Tenant display name")


class ScanContext(BaseModel):
    """Scan execution context."""
    scan_run_id: str = Field(..., description="Unique scan run identifier")
    trigger_type: TriggerType = Field(..., description="How the scan was triggered")
    cloud: Cloud = Field(..., description="Cloud service provider")
    collection_mode: CollectionMode = Field(..., description="Full or incremental scan")
    providers: Optional[List[str]] = Field(None, description="List of providers scanned")
    regions: Optional[List[str]] = Field(None, description="List of regions scanned")
    scope: Optional[Dict[str, Any]] = Field(None, description="Scan scope details")
    engine_versions: Optional[Dict[str, str]] = Field(None, description="Engine version info")
    started_at: str = Field(..., description="ISO8601 timestamp when scan started")
    completed_at: str = Field(..., description="ISO8601 timestamp when scan completed")


class ComplianceMapping(BaseModel):
    """Mapping of finding to compliance framework control."""
    framework_id: str = Field(..., description="Framework identifier (e.g., CIS, ISO27001)")
    framework_version: Optional[str] = Field(None, description="Framework version")
    control_id: str = Field(..., description="Control identifier within framework")
    control_title: Optional[str] = Field(None, description="Control title")


class AffectedAsset(BaseModel):
    """Asset affected by a finding."""
    asset_id: str = Field(..., description="Unique asset identifier (typically ARN)")
    provider: str = Field(..., description="Cloud provider")
    resource_type: str = Field(..., description="Resource type (e.g., s3_bucket)")
    resource_id: str = Field(..., description="Resource identifier")
    region: Optional[str] = Field(None, description="AWS region or equivalent")
    arn: Optional[str] = Field(None, description="Full ARN if applicable")
    tags: Optional[Dict[str, str]] = Field(None, description="Resource tags")


class Evidence(BaseModel):
    """Evidence for a finding (stored by reference)."""
    evidence_id: str = Field(..., description="Unique evidence identifier")
    type: EvidenceType = Field(..., description="Type of evidence")
    data_ref: str = Field(..., description="S3 path to evidence payload")
    collected_at: str = Field(..., description="ISO8601 timestamp when evidence collected")


class Remediation(BaseModel):
    """Remediation information for a finding."""
    description: str = Field(..., description="Remediation description")
    steps: Optional[List[str]] = Field(None, description="Step-by-step remediation")
    automated: bool = Field(False, description="Whether remediation can be automated")
    estimated_effort: Optional[Literal["low", "medium", "high"]] = Field(None, description="Estimated effort")


class Finding(BaseModel):
    """Individual misconfiguration finding."""
    finding_id: str = Field(..., description="Stable finding identifier (deduplicated)")
    rule_id: str = Field(..., description="Rule identifier that triggered this finding")
    rule_version: Optional[str] = Field(None, description="Rule version")
    category: Optional[str] = Field(None, description="Finding category (e.g., data_protection)")
    title: str = Field(..., description="Finding title")
    description: Optional[str] = Field(None, description="Finding description")
    severity: Severity = Field(..., description="Finding severity")
    confidence: Confidence = Field(Confidence.HIGH, description="Confidence level")
    status: FindingStatus = Field(FindingStatus.OPEN, description="Finding status")
    first_seen_at: str = Field(..., description="ISO8601 timestamp when first seen")
    last_seen_at: str = Field(..., description="ISO8601 timestamp when last seen")
    compliance_mappings: List[ComplianceMapping] = Field(default_factory=list, description="Framework mappings")
    affected_assets: List[AffectedAsset] = Field(..., description="Affected assets")
    evidence: List[Evidence] = Field(default_factory=list, description="Evidence references")
    remediation: Optional[Remediation] = Field(None, description="Remediation information")


class Control(BaseModel):
    """Compliance framework control."""
    control_id: str = Field(..., description="Control identifier")
    control_title: str = Field(..., description="Control title")
    status: ControlStatus = Field(..., description="Control compliance status")
    finding_refs: List[str] = Field(default_factory=list, description="Finding IDs for this control")
    asset_count_passed: int = Field(0, description="Number of assets passing this control")
    asset_count_failed: int = Field(0, description="Number of assets failing this control")
    asset_count_total: int = Field(0, description="Total assets checked for this control")


class Section(BaseModel):
    """Framework section containing controls."""
    section_id: str = Field(..., description="Section identifier")
    section_title: str = Field(..., description="Section title")
    controls: List[Control] = Field(default_factory=list, description="Controls in this section")


class Framework(BaseModel):
    """Compliance framework."""
    framework_id: str = Field(..., description="Framework identifier")
    framework_version: Optional[str] = Field(None, description="Framework version")
    framework_name: str = Field(..., description="Framework display name")
    sections: List[Section] = Field(default_factory=list, description="Framework sections")


class PostureSummary(BaseModel):
    """Overall compliance posture summary."""
    total_controls: int = Field(0, description="Total controls assessed")
    controls_passed: int = Field(0, description="Controls that passed")
    controls_failed: int = Field(0, description="Controls that failed")
    controls_not_applicable: int = Field(0, description="Controls not applicable")
    total_findings: int = Field(0, description="Total findings")
    findings_by_severity: Dict[str, int] = Field(default_factory=dict, description="Findings count by severity")
    findings_by_status: Dict[str, int] = Field(default_factory=dict, description="Findings count by status")
    per_control_asset_counts: Optional[Dict[str, Dict[str, int]]] = Field(None, description="Per-control asset counts")


class AssetSnapshot(BaseModel):
    """Snapshot of scanned asset."""
    asset_id: str = Field(..., description="Unique asset identifier")
    provider: str = Field(..., description="Cloud provider")
    resource_type: str = Field(..., description="Resource type")
    resource_id: str = Field(..., description="Resource identifier")
    region: Optional[str] = Field(None, description="Region")
    arn: Optional[str] = Field(None, description="Full ARN")
    tags: Optional[Dict[str, str]] = Field(None, description="Resource tags")
    graph_ref: Optional[str] = Field(None, description="Reference to resource graph")


class Integrity(BaseModel):
    """Report integrity information."""
    report_hash: Optional[str] = Field(None, description="SHA256 hash of report")
    generated_at: str = Field(..., description="ISO8601 timestamp when report generated")
    generator_version: str = Field(..., description="Compliance engine version")


class EnterpriseComplianceReport(BaseModel):
    """Enterprise-grade compliance report (cspm_misconfig_report.v1)."""
    schema_version: Literal["cspm_misconfig_report.v1"] = "cspm_misconfig_report.v1"
    tenant: Tenant = Field(..., description="Tenant information")
    scan_context: ScanContext = Field(..., description="Scan execution context")
    posture_summary: PostureSummary = Field(..., description="Compliance posture summary")
    findings: List[Finding] = Field(default_factory=list, description="All findings")
    frameworks: List[Framework] = Field(default_factory=list, description="Compliance frameworks")
    asset_snapshots: List[AssetSnapshot] = Field(default_factory=list, description="Scanned assets")
    integrity: Integrity = Field(..., description="Report integrity")

    class Config:
        json_schema_extra = {
            "example": {
                "schema_version": "cspm_misconfig_report.v1",
                "tenant": {
                    "tenant_id": "tenant-123",
                    "tenant_name": "Acme Corp"
                },
                "scan_context": {
                    "scan_run_id": "scan-456",
                    "trigger_type": "scheduled",
                    "cloud": "aws",
                    "collection_mode": "full",
                    "started_at": "2026-01-13T10:00:00Z",
                    "completed_at": "2026-01-13T10:30:00Z"
                },
                "posture_summary": {
                    "total_controls": 100,
                    "controls_passed": 80,
                    "controls_failed": 20,
                    "total_findings": 45
                },
                "findings": [],
                "frameworks": [],
                "asset_snapshots": [],
                "integrity": {
                    "generated_at": "2026-01-13T10:30:00Z",
                    "generator_version": "1.0.0"
                }
            }
        }

