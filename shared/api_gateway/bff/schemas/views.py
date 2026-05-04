"""TypedDict schemas for all BFF view responses — DI-09.

All field names use camelCase to match React / frontend conventions.
Use ``Optional`` for fields that may be absent when data is unavailable.

These schemas are informational / type-checking only.  The BFF handlers
return plain dicts — mypy or pyright can validate against these types.

Usage example:
    from bff.schemas.views import DashboardView
    result: DashboardView = {...}
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict


# ── Shared primitives ─────────────────────────────────────────────────────────


class KpiItem(TypedDict):
    """A single KPI metric cell."""

    label: str
    value: Any                          # int | float | str
    suffix: Optional[str]               # e.g. "/100", "%"


class KpiGroup(TypedDict):
    """A named group of KPI cells (renders as a strip)."""

    title: str
    items: List[KpiItem]


class ScanMeta(TypedDict):
    """Metadata about the scan run that produced this view's data."""

    scanRunId: str
    latestDetection: Optional[str]      # ISO timestamp
    dataScope: str                      # "latest" | "single_scan"


class ThreatItem(TypedDict):
    """A single normalized threat detection."""

    scenario_id: Optional[str]
    title: str
    severity: str                       # critical | high | medium | low
    riskScore: Optional[int]            # 0-100
    resourceUid: Optional[str]
    resourceType: Optional[str]
    accountId: Optional[str]
    region: Optional[str]
    provider: Optional[str]
    mitreTactics: Optional[List[str]]
    mitreTechniqueIds: Optional[List[str]]
    detectedAt: Optional[str]           # ISO timestamp
    lastSeen: Optional[str]             # ISO timestamp
    hasAttackPath: Optional[bool]
    isInternetExposed: Optional[bool]
    contributingFindings: Optional[List[Dict[str, Any]]]


class RiskScenario(TypedDict):
    """A single FAIR risk scenario."""

    scenarioId: Optional[str]
    scenarioName: str
    threatCategory: Optional[str]
    probability: Optional[float]        # 0.0–1.0
    expectedLoss: Optional[float]
    worstCaseLoss: Optional[float]
    riskRating: Optional[str]           # critical | high | medium | low
    account: Optional[str]


class FrameworkScore(TypedDict):
    """Compliance framework summary row."""

    id: Optional[str]
    name: str
    version: Optional[str]
    score: float                        # 0–100
    controls: int
    passed: int
    failed: int
    hasAssessment: Optional[bool]
    lastAssessed: Optional[str]


# ── Page-level view schemas ───────────────────────────────────────────────────


class DashboardView(TypedDict):
    """Response shape for GET /api/v1/views/dashboard."""

    pageContext: Dict[str, Any]
    kpi: Dict[str, Any]                 # totalAssets, openFindings, …
    chartCategories: List[Dict[str, Any]]
    criticalActions: Dict[str, Any]     # immediate, thisWeek, thisMonth lists
    toxicCombinations: List[Dict[str, Any]]
    criticalAlerts: List[Dict[str, Any]]
    recentThreats: List[ThreatItem]


class ThreatsView(TypedDict):
    """Response shape for GET /api/v1/views/threats."""

    pageContext: Dict[str, Any]
    filterSchema: List[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    scanMeta: ScanMeta
    threats: List[ThreatItem]
    threatFindings: List[Dict[str, Any]]
    total: int
    trendData: List[Dict[str, Any]]
    mitreMatrix: Dict[str, List[Dict[str, Any]]]
    attackChains: List[Dict[str, Any]]
    threatIntel: List[Dict[str, Any]]
    accountHeatmap: List[Dict[str, Any]]
    kpi: Dict[str, Any]                 # legacy alias


class ComplianceView(TypedDict):
    """Response shape for GET /api/v1/views/compliance."""

    pageContext: Dict[str, Any]
    filterSchema: List[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    frameworks: List[FrameworkScore]
    failingControls: List[Dict[str, Any]]
    trendData: List[Dict[str, Any]]
    auditDeadlines: List[Dict[str, Any]]
    exceptions: List[Dict[str, Any]]
    accountMatrix: List[Dict[str, Any]]


class InventoryView(TypedDict):
    """Response shape for GET /api/v1/views/inventory."""

    pageContext: Dict[str, Any]
    filterSchema: List[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    scanMeta: ScanMeta
    assets: List[Dict[str, Any]]
    total: int
    byProvider: Dict[str, int]
    byRegion: Dict[str, int]
    byType: Dict[str, int]
    trendData: List[Dict[str, Any]]


class IamView(TypedDict):
    """Response shape for GET /api/v1/views/iam."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    byProvider: Optional[Dict[str, Any]]
    riskySummary: Optional[Dict[str, Any]]


class RiskView(TypedDict):
    """Response shape for GET /api/v1/views/risk."""

    pageContext: Dict[str, Any]
    kpiGroups: List[KpiGroup]
    riskCategories: List[Dict[str, Any]]
    riskRegister: List[Dict[str, Any]]
    scenarios: List[RiskScenario]
    trendData: List[Dict[str, Any]]
    mitigationRoadmap: List[Dict[str, Any]]
    topAssets: List[Dict[str, Any]]


class MisconfigView(TypedDict):
    """Response shape for GET /api/v1/views/misconfig."""

    pageContext: Dict[str, Any]
    filterSchema: List[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    scanMeta: Optional[ScanMeta]
    findings: List[Dict[str, Any]]
    total: int
    byService: Optional[Dict[str, Any]]
    bySeverity: Optional[Dict[str, Any]]


class NetworkSecurityView(TypedDict):
    """Response shape for GET /api/v1/views/network-security."""

    pageContext: Dict[str, Any]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    byLayer: Optional[Dict[str, Any]]
    byProvider: Optional[Dict[str, Any]]
    trendData: Optional[List[Dict[str, Any]]]


class CiemView(TypedDict):
    """Response shape for GET /api/v1/views/ciem."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    byProvider: Optional[Dict[str, Any]]
    byCategory: Optional[Dict[str, Any]]


class VulnerabilityView(TypedDict):
    """Response shape for GET /api/v1/views/vulnerability."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    bySeverity: Optional[Dict[str, Any]]
    byPackage: Optional[List[Dict[str, Any]]]
    trendData: Optional[List[Dict[str, Any]]]


class DatasecView(TypedDict):
    """Response shape for GET /api/v1/views/datasec."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    byClassification: Optional[Dict[str, Any]]
    byProvider: Optional[Dict[str, Any]]


class EncryptionView(TypedDict):
    """Response shape for GET /api/v1/views/encryption."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    unencryptedCount: Optional[int]


class ContainerSecView(TypedDict):
    """Response shape for GET /api/v1/views/container-security."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    bySeverity: Optional[Dict[str, Any]]
    imageRisks: Optional[List[Dict[str, Any]]]


class AiSecurityView(TypedDict):
    """Response shape for GET /api/v1/views/ai-security."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    modelRisks: Optional[List[Dict[str, Any]]]
    byCategory: Optional[Dict[str, Any]]


class DbsecView(TypedDict):
    """Response shape for GET /api/v1/views/database-security."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    byEngine: Optional[Dict[str, Any]]
    publicDatabases: Optional[int]


class CwppView(TypedDict):
    """Response shape for GET /api/v1/views/cwpp."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    findings: List[Dict[str, Any]]
    total: int
    workloadRisks: Optional[List[Dict[str, Any]]]


class CnappView(TypedDict):
    """Response shape for GET /api/v1/views/cnapp."""

    pageContext: Optional[Dict[str, Any]]
    kpiGroups: List[KpiGroup]
    pillars: Optional[List[Dict[str, Any]]]
    total: int
    overallScore: Optional[int]
