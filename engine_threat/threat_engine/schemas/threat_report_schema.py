"""
Threat Report Schema (cspm_threat_report.v1)

This module defines the threat report structure with:
- Tenant and scan context
- Threat detections with misconfig correlations
- Normalized misconfig findings
- Asset snapshots
- Threat summary with per-category counts
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
    K8S = "k8s"


class ThreatType(str, Enum):
    EXPOSURE = "exposure"
    IDENTITY = "identity"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MISCONFIGURATION = "misconfiguration"
    NETWORK = "network"
    DATA_BREACH = "data_breach"
    COMPLIANCE_VIOLATION = "compliance_violation"
    CONFIGURATION_DRIFT = "configuration_drift"
    CHECK_STATUS_DRIFT = "check_status_drift"


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


class ThreatStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"


class EvidenceType(str, Enum):
    MISCONFIG = "misconfig"
    INVENTORY = "inventory"
    GRAPH = "graph"
    LOG = "log"


class Tenant(BaseModel):
    tenant_id: str = Field(..., description="Unique tenant identifier")
    tenant_name: Optional[str] = Field(None, description="Human-readable tenant name")


class ScanContext(BaseModel):
    scan_run_id: str = Field(..., description="Unique scan run identifier")
    trigger_type: TriggerType = Field(..., description="How the scan was triggered")
    cloud: Cloud = Field(..., description="Cloud provider")
    accounts: List[str] = Field(default_factory=list, description="List of account IDs")
    regions: List[str] = Field(default_factory=list, description="List of regions scanned")
    services: List[str] = Field(default_factory=list, description="List of services scanned")
    started_at: datetime = Field(..., description="Scan start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")
    engine_version: Optional[str] = Field(None, description="ConfigScan engine version")


class MisconfigFinding(BaseModel):
    """Normalized misconfig finding from scan output with MITRE ATT&CK enrichment"""
    misconfig_finding_id: str = Field(..., description="Stable finding identifier")
    finding_key: str = Field(..., description="Composite key: rule_id|resource_uid|account|region")
    rule_id: str = Field(..., description="Rule identifier")
    severity: Severity = Field(..., description="Severity level")
    result: Literal["PASS", "FAIL", "WARN"] = Field(..., description="Check result")
    account: str = Field(..., description="Account ID")
    region: str = Field(..., description="Region code")
    service: str = Field(..., description="Service name")
    resource: Dict[str, Any] = Field(..., description="Resource details (resource_uid, resource_arn, resource_id, resource_type, tags)")
    evidence_refs: List[str] = Field(default_factory=list, description="Evidence reference IDs")
    checked_fields: List[str] = Field(default_factory=list, description="Fields that were checked")
    first_seen_at: Optional[datetime] = Field(None, description="First detection timestamp")
    last_seen_at: Optional[datetime] = Field(None, description="Last detection timestamp")
    # MITRE ATT&CK enrichment (from rule_metadata JOIN)
    threat_category: Optional[str] = Field(None, description="Threat category from rule_metadata")
    threat_tags: Optional[List[str]] = Field(default_factory=list, description="Threat tags")
    risk_score: Optional[int] = Field(None, description="Risk score (0-100)")
    mitre_techniques: Optional[List[str]] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    mitre_tactics: Optional[List[str]] = Field(default_factory=list, description="MITRE ATT&CK tactic names")
    # Rule metadata (from rule_metadata JOIN)
    title: Optional[str] = Field(None, description="Rule title from metadata")
    description: Optional[str] = Field(None, description="Rule description from metadata")
    remediation: Optional[str] = Field(None, description="Remediation guidance from metadata")
    domain: Optional[str] = Field(None, description="Security domain from metadata")


class ThreatCorrelation(BaseModel):
    """Correlation between threat and misconfig findings"""
    misconfig_finding_refs: List[str] = Field(..., description="List of misconfig finding IDs that enabled this threat")
    affected_assets: List[Dict[str, Any]] = Field(default_factory=list, description="Affected asset details")


class DriftEvent(BaseModel):
    """Drift event details for configuration or check-status changes"""
    drift_type: str = Field(..., description="Drift type (configuration, check_status)")
    discovery_id: Optional[str] = Field(None, description="Discovery ID associated with drift")
    rule_id: Optional[str] = Field(None, description="Rule ID for check status drift")
    resource_arn: Optional[str] = Field(None, description="Resource ARN")
    resource_uid: Optional[str] = Field(None, description="Resource UID")
    service: Optional[str] = Field(None, description="Service name")
    region: Optional[str] = Field(None, description="Region")
    baseline_scan_id: Optional[str] = Field(None, description="Baseline scan ID used for comparison")
    current_scan_id: Optional[str] = Field(None, description="Current scan ID")
    change_summary: Optional[Dict[str, Any]] = Field(None, description="Change summary or diff details")
    previous_hash: Optional[str] = Field(None, description="Previous configuration hash")
    current_hash: Optional[str] = Field(None, description="Current configuration hash")


class Threat(BaseModel):
    """Individual threat detection with MITRE ATT&CK enrichment"""
    threat_id: str = Field(..., description="Stable threat identifier")
    threat_type: ThreatType = Field(..., description="Threat category")
    title: str = Field(..., description="Threat title")
    description: str = Field(..., description="Detailed threat description")
    severity: Severity = Field(..., description="Threat severity")
    confidence: Confidence = Field(..., description="Detection confidence")
    status: ThreatStatus = Field(default=ThreatStatus.OPEN, description="Threat status")
    first_seen_at: datetime = Field(..., description="First detection timestamp")
    last_seen_at: datetime = Field(..., description="Last detection timestamp")
    correlations: ThreatCorrelation = Field(..., description="Correlation with misconfig findings")
    affected_assets: List[Dict[str, Any]] = Field(default_factory=list, description="Affected assets")
    evidence_refs: List[str] = Field(default_factory=list, description="Evidence reference IDs")
    remediation: Optional[Dict[str, Any]] = Field(None, description="Remediation guidance")
    drift: Optional[DriftEvent] = Field(None, description="Drift details if threat is drift-related")
    # MITRE ATT&CK enrichment
    mitre_techniques: Optional[List[str]] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    mitre_tactics: Optional[List[str]] = Field(default_factory=list, description="MITRE ATT&CK tactic names")
    risk_score: Optional[int] = Field(None, description="Aggregated risk score (0-100)")


class ThreatAnalysisResult(BaseModel):
    """Individual threat analysis with blast radius, risk scoring and attack chain"""
    analysis_id: Optional[str] = Field(None, description="Analysis UUID (set by DB)")
    detection_id: str = Field(..., description="FK to threat_detections.detection_id")
    tenant_id: str = Field(..., description="Tenant identifier")
    analysis_type: str = Field(default="risk_triage", description="Analysis type (risk_triage, blast_radius)")
    analyzer: str = Field(default="threat_analyzer.v1", description="Analyzer version")
    analysis_status: str = Field(default="completed", description="pending|running|completed|failed")
    risk_score: Optional[int] = Field(None, description="Composite risk score (0-100)")
    verdict: Optional[str] = Field(None, description="Human-readable verdict")
    analysis_results: Dict[str, Any] = Field(default_factory=dict, description="Blast radius, MITRE impact, reachability")
    recommendations: List[Dict[str, Any]] = Field(default_factory=list, description="Prioritized recommendations")
    related_threats: List[str] = Field(default_factory=list, description="Related detection IDs")
    attack_chain: List[Dict[str, Any]] = Field(default_factory=list, description="Ordered attack chain steps")
    started_at: Optional[datetime] = Field(None, description="Analysis start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Analysis completion timestamp")


class ThreatSummary(BaseModel):
    """Summary statistics for threats"""
    total_threats: int = Field(..., description="Total number of threats")
    threats_by_severity: Dict[str, int] = Field(default_factory=dict, description="Count by severity")
    threats_by_category: Dict[str, int] = Field(default_factory=dict, description="Count by threat type")
    threats_by_status: Dict[str, int] = Field(default_factory=dict, description="Count by status")
    top_threat_categories: List[Dict[str, Any]] = Field(default_factory=list, description="Top threat categories with counts")


class AssetSnapshot(BaseModel):
    """Asset snapshot for threat context"""
    asset_id: str = Field(..., description="Asset identifier")
    provider: Cloud = Field(..., description="Cloud provider")
    resource_type: str = Field(..., description="Resource type")
    resource_id: Optional[str] = Field(None, description="Resource ID")
    resource_arn: Optional[str] = Field(None, description="Resource ARN")
    region: Optional[str] = Field(None, description="Region")
    account: Optional[str] = Field(None, description="Account ID")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")


class Evidence(BaseModel):
    """Evidence reference for threat"""
    evidence_id: str = Field(..., description="Evidence identifier")
    type: EvidenceType = Field(..., description="Evidence type")
    data_ref: str = Field(..., description="Reference to evidence data (S3 path or local path)")
    collected_at: datetime = Field(..., description="Evidence collection timestamp")


class ThreatReport(BaseModel):
    """Complete threat report"""
    schema_version: Literal["cspm_threat_report.v1"] = "cspm_threat_report.v1"
    tenant: Tenant = Field(..., description="Tenant information")
    scan_context: ScanContext = Field(..., description="Scan context")
    threat_summary: ThreatSummary = Field(..., description="Threat summary statistics")
    threats: List[Threat] = Field(default_factory=list, description="List of detected threats")
    misconfig_findings: List[MisconfigFinding] = Field(default_factory=list, description="Normalized misconfig findings")
    asset_snapshots: List[AssetSnapshot] = Field(default_factory=list, description="Asset snapshots")
    evidence: List[Evidence] = Field(default_factory=list, description="Evidence references")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Report generation timestamp")

