"""BFF schema: /dashboard view (Executive Security Dashboard).

Source of truth: shared/api_gateway/bff/dashboard.py return{}
Engines: threat, compliance, inventory, iam, datasec, risk, onboarding (7 parallel calls)
UI: frontend/src/app/dashboard/page.jsx

Unique pattern: this view uses chartCategories[] instead of kpiGroups[].
Dashboard has NO per-page fetchView call from the UI — each widget section
calls fetchView(config.bffView) individually. The schema here covers the
full aggregated response returned by GET /api/v1/views/dashboard.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "DashboardKpi",
    "ChartDataPoint",
    "Chart",
    "ChartCategory",
    "CriticalAction",
    "ToxicCombination",
    "CriticalAlert",
    "RecentThreat",
    "ScanMeta",
    "DashboardResponse",
]


class DashboardKpi(BaseModel):
    """Top-strip KPI metrics for the dashboard hero row."""

    totalFindings: int = 0
    totalAssets: int = 0
    criticalFindings: int = 0
    highFindings: int = 0
    complianceScore: float = 0.0
    riskScore: float = 0.0
    iamFindings: int = 0
    datasecFindings: int = 0

    model_config = ConfigDict(extra="allow")


class ChartDataPoint(BaseModel):
    """Generic chart data point — shape varies per chart type."""

    model_config = ConfigDict(extra="allow")


class Chart(BaseModel):
    """One chart widget inside a ChartCategory."""

    id: str
    type: str
    title: str
    data: List[Any] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class ChartCategory(BaseModel):
    """Section grouping related charts (security_posture, threats, assets, operations)."""

    id: str
    title: str
    charts: List[Chart] = Field(default_factory=list)


class CriticalAction(BaseModel):
    """One item in a Critical Actions urgency bucket."""

    model_config = ConfigDict(extra="allow")


class ToxicCombination(BaseModel):
    """One toxic combination (co-occurring high-risk findings)."""

    model_config = ConfigDict(extra="allow")


class CriticalAlert(BaseModel):
    """One critical-alert banner entry."""

    model_config = ConfigDict(extra="allow")


class RecentThreat(BaseModel):
    """One recent threat detection surfaced on the dashboard."""

    model_config = ConfigDict(extra="allow")


class ScanMeta(BaseModel):
    """Scan context metadata attached to the dashboard response."""

    scanRunId: str = ""
    dataScope: str = "all_scans"
    hasData: bool = False


class DashboardResponse(BaseModel):
    """Full response shape for GET /api/v1/views/dashboard."""

    pageContext: Dict[str, Any] = Field(default_factory=dict)
    kpi: DashboardKpi = Field(default_factory=DashboardKpi)
    riskMatrix: List[Dict[str, Any]] = Field(default_factory=list)
    chartCategories: List[ChartCategory] = Field(default_factory=list)
    criticalActions: Dict[str, List[CriticalAction]] = Field(default_factory=dict)
    toxicCombinations: List[ToxicCombination] = Field(default_factory=list)
    criticalAlerts: List[CriticalAlert] = Field(default_factory=list)
    recentThreats: List[RecentThreat] = Field(default_factory=list)
    scanMeta: ScanMeta = Field(default_factory=ScanMeta)
    _meta: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")
