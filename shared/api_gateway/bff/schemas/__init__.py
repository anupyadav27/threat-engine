"""BFF contract schemas package.

Single import surface for all Pydantic response models and shared base types.

Usage
-----
# New schema files (Phase 1+):
from shared.api_gateway.bff.schemas import (
    BaseFindingItem,
    BFFErrorResponse,
    CSPProvider,
    KpiGroup,
    PageContext,
    SeverityCounts,
)

# Finding-detail handler:
from shared.api_gateway.bff.schemas.findings import (
    FindingDetailResponse,
    FindingHeader,
)

# Per-view models (added in Phase 1+):
from shared.api_gateway.bff.schemas.dashboard import DashboardResponse
from shared.api_gateway.bff.schemas.risk import RiskResponse
# etc.
"""

from ._common import (  # noqa: F401
    BaseFindingItem,
    BFFErrorResponse,
    CSPProvider,
    FilterField,
    KpiGroup,
    KpiItem,
    PageContext,
    PageTab,
    PaginatedList,
    ScanRunRef,
    SeverityCounts,
    _BaseViewResponse,
)

from .misconfig import (  # noqa: F401
    MisconfigFinding,
    MisconfigKpi,
    MisconfigResponse,
    HeatmapCell,
    ScanTrendPoint as MisconfigScanTrendPoint,
)
from .network_security import (  # noqa: F401
    NetworkFinding,
    NetworkSecurityResponse,
    ModuleScoreItem,
)
from .threat_command_room import (  # noqa: F401
    ThreatScenario,
    PulseStats,
    ThreatCommandRoomResponse,
)
from .risk import (  # noqa: F401
    RiskScenario,
    RiskCategory,
    RiskResponse,
    MitigationStep,
)
from .dashboard import (  # noqa: F401
    DashboardKpi,
    DashboardResponse,
    ChartCategory,
)
from .encryption import (  # noqa: F401
    EncryptionFinding,
    EncryptionResponse,
    EncryptionKpiItem,
    ModuleScoreItem as EncryptionModuleScoreItem,
)
from .database_security import (  # noqa: F401
    DatabaseItem,
    DatabaseFinding,
    DatabaseSecurityResponse,
)
from .container_security import (  # noqa: F401
    ClusterItem,
    ContainerFinding,
    ContainerSecurityResponse,
)
from .vulnerability import (  # noqa: F401
    AgentItem,
    VulnerabilityResponse,
)
from .secops import (  # noqa: F401
    ScanRecord,
    SecopsAggregate,
    SecopsResponse,
)
from .findings import (  # noqa: F401
    ComplianceBlock,
    ComplianceMappingItem,
    EngineExtensions,
    EngineSlug,
    FindingDetailResponse,
    FindingHeader,
    RelatedFinding,
    RelatedFindingsBlock,
    RemediationBlock,
    RemediationStep,
    StandardColumns,
    StatusUpdateRequest,
)
from .threat_attack_paths import (  # noqa: F401
    AttackPathItem,
    AttackPathKpi,
    ThreatAttackPathsResponse,
)
from .threat_blast_radius import (  # noqa: F401
    BlastRadiusItem,
    BlastRadiusKpi,
    ThreatBlastRadiusResponse,
)
from .threat_toxic_combos import (  # noqa: F401
    ToxicComboKpi,
    ThreatToxicCombosResponse,
)
from .threat_timeline import (  # noqa: F401
    TimelineEventKpi,
    ThreatTimelineResponse,
)
from .billing import (  # noqa: F401
    BillingResponse,
    BillingDataWrapper,
)
from .scans import (  # noqa: F401
    ScansResponse,
    ScanStats,
)
from .reports import (  # noqa: F401
    ReportsResponse,
    ReportsKpi,
    ReportTemplate,
)
from .rules import (  # noqa: F401
    RulesResponse,
    RuleSummary,
)
from .cnapp import (  # noqa: F401
    CNAPPResponse,
    PillarItem,
)
from .cwpp import (  # noqa: F401
    CWPPResponse,
    CWPPWorkload,
)
from .ai_security import (  # noqa: F401
    AISecurityResponse,
    AICoverageMetrics,
)
from .threat_graph import (  # noqa: F401
    ThreatGraphResponse,
    NodeSecurityResponse,
    GraphKpi,
)

__all__ = [
    # CSP type
    "CSPProvider",
    # Base models
    "BaseFindingItem",
    "SeverityCounts",
    # Error + pagination
    "BFFErrorResponse",
    "PaginatedList",
    "ScanRunRef",
    # Envelope helpers
    "KpiItem",
    "KpiGroup",
    "PageTab",
    "PageContext",
    "FilterField",
    "_BaseViewResponse",
    # Finding detail models
    "ComplianceBlock",
    "ComplianceMappingItem",
    "EngineExtensions",
    "EngineSlug",
    "FindingDetailResponse",
    "FindingHeader",
    "RelatedFinding",
    "RelatedFindingsBlock",
    "RemediationBlock",
    "RemediationStep",
    "StandardColumns",
    "StatusUpdateRequest",
    # Sprint 2 — view-specific schemas
    "MisconfigFinding",
    "MisconfigKpi",
    "MisconfigResponse",
    "NetworkFinding",
    "NetworkSecurityResponse",
    "ModuleScoreItem",
    "ThreatScenario",
    "PulseStats",
    "ThreatCommandRoomResponse",
    "RiskScenario",
    "RiskCategory",
    "RiskResponse",
    "MitigationStep",
    "DashboardKpi",
    "DashboardResponse",
    "ChartCategory",
    # Sprint 3 — security engine schemas
    "EncryptionFinding",
    "EncryptionResponse",
    "DatabaseItem",
    "DatabaseFinding",
    "DatabaseSecurityResponse",
    "ClusterItem",
    "ContainerFinding",
    "ContainerSecurityResponse",
    "AgentItem",
    "VulnerabilityResponse",
    "ScanRecord",
    "SecopsAggregate",
    "SecopsResponse",
    # Sprint 4 — threat sub-views + operational
    "AttackPathItem",
    "AttackPathKpi",
    "ThreatAttackPathsResponse",
    "BlastRadiusItem",
    "BlastRadiusKpi",
    "ThreatBlastRadiusResponse",
    "ToxicComboKpi",
    "ThreatToxicCombosResponse",
    "TimelineEventKpi",
    "ThreatTimelineResponse",
    "BillingResponse",
    "BillingDataWrapper",
    "ScansResponse",
    "ScanStats",
    "ReportsResponse",
    "ReportsKpi",
    "ReportTemplate",
    "RulesResponse",
    "RuleSummary",
    "CNAPPResponse",
    "PillarItem",
    "CWPPResponse",
    "CWPPWorkload",
    "AISecurityResponse",
    "AICoverageMetrics",
    "ThreatGraphResponse",
    "NodeSecurityResponse",
    "GraphKpi",
]
