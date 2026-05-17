"""
Pydantic response models for the threat_v1 REST API (S4-02).

Two model tiers per REQUIREMENTS §4 and Sprint Plan S4-02:

  IncidentListItem — strips PII (actor_principal, source_ip, action, graph_query)
  IncidentDetail   — all fields, requires cdr:sensitive permission for CDR fields

CP1-02 enforcement: actor_principal NEVER appears in any response model.
Only actor_hash is exposed, and only in IncidentDetail when caller has cdr:sensitive.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class CDREventSummary(BaseModel):
    """CDR event in list view — technique only, no PII."""

    finding_id: str
    mitre_technique: str
    mitre_tactic: str
    event_time: Optional[datetime] = None
    anomaly_score: float = 0.0
    # actor_principal is NEVER included — CP1-02


class CDREventDetail(CDREventSummary):
    """CDR event in detail view — includes actor_hash only (not raw actor_principal)."""

    actor_hash: Optional[str] = None  # sha256 of actor_principal — never raw value


class MisconfigFindingSummary(BaseModel):
    finding_id: str
    rule_id: str
    severity: str
    title: str
    mitre_techniques: List[str] = Field(default_factory=list)
    status: str


class VulnFindingSummary(BaseModel):
    cve_id: str
    cvss_score: float
    epss_score: float
    has_known_exploit: bool
    mitre_technique: Optional[str] = None
    package: Optional[str] = None
    fixed_version: Optional[str] = None


class IncidentListItem(BaseModel):
    """Incident in list/table view. Strips all CDR PII fields."""

    incident_id: str = Field(alias="dedup_key")
    tenant_id: str
    account_id: Optional[str] = None
    region: Optional[str] = None
    entry_resource_uid: Optional[str] = None
    target_resource_uid: Optional[str] = None
    primary_pattern_id: Optional[str] = None
    matched_patterns: List[str] = Field(default_factory=list)
    tier: int
    incident_class: Literal["posture", "suspicious", "active"]
    severity: Literal["critical", "high", "medium", "low"]
    status: str
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    title: Optional[str] = None
    story_text: Optional[str] = None
    cdr_technique_count: int = 0

    model_config = {"populate_by_name": True}


class IncidentDetail(IncidentListItem):
    """Full incident detail — CDR fields gated by cdr:sensitive permission."""

    hop_resource_uids: List[str] = Field(default_factory=list)
    misconfig_findings: List[MisconfigFindingSummary] = Field(default_factory=list)
    vuln_findings: List[VulnFindingSummary] = Field(default_factory=list)
    # cdr_events populated only when caller has cdr:sensitive
    cdr_events: List[CDREventDetail] = Field(default_factory=list)
    resolved_at: Optional[datetime] = None
    scan_run_id: Optional[str] = None


class IncidentListResponse(BaseModel):
    items: List[IncidentListItem]
    total: int
    page: int
    page_size: int


class ScanStatusResponse(BaseModel):
    scan_run_id: str
    status: str
    resource_count: int = 0
    misconfig_count: int = 0
    vuln_count: int = 0
    cdr_event_count: int = 0
    edge_count: int = 0
    crown_jewel_count: int = 0
    patterns_run: int = 0
    incidents_written: int = 0
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str = "engine-threat-v1"
    version: str = "1.0.0"
