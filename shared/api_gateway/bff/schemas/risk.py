"""BFF schema: /risk view (Risk Quantification — FAIR model).

Source of truth: shared/api_gateway/bff/risk.py return{}
Engine: risk engine /api/v1/risk/ui-data + threat engine /api/v1/threat/ui-data
UI: frontend/src/app/risk/page.jsx

Four tabs: overview, scenarios (FAIR), register, roadmap
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ._common import FilterField, KpiGroup, PageContext, _BaseViewResponse

__all__ = [
    "RiskScenario",
    "RiskCategory",
    "RiskRegisterItem",
    "MitigationStep",
    "TopAsset",
    "RiskTrendPoint",
    "RiskComparisonPoint",
    "RiskResponse",
]


class RiskScenario(BaseModel):
    """One FAIR risk scenario (normalised by normalize_risk_scenario)."""

    scenario_name: str = ""
    risk_rating: str = "low"
    expected_loss: float = 0.0
    worst_case_loss: float = 0.0
    probability: float = 0.0
    account: str = ""

    model_config = ConfigDict(extra="allow")


class RiskCategory(BaseModel):
    """Risk domain breakdown item (IAM, Network, DataSec, etc.)."""

    category: str
    score: float = 0.0
    count: int = 0
    weight: float = 0.0

    model_config = ConfigDict(extra="allow")


class RiskRegisterItem(BaseModel):
    """One row in the risk register table."""

    model_config = ConfigDict(extra="allow")


class MitigationStep(BaseModel):
    """One item in the mitigation roadmap."""

    id: str = ""
    action: str = ""
    scenario: str = ""
    current_risk: float = 0.0
    target_risk: float = 0.0
    cost: str = ""
    priority: str = "High"
    risk_reduction: int = 0
    effort: str = "Medium"
    status: str = "planned"
    owner: str = ""
    due_date: str = ""

    model_config = ConfigDict(extra="allow")


class TopAsset(BaseModel):
    """High-risk asset from the risk engine top-assets endpoint."""

    blast_radius_score: int = 0
    compound_risk_score: int = 0

    model_config = ConfigDict(extra="allow")


class RiskTrendPoint(BaseModel):
    """One data point in the risk trend sparkline (activeScanTrend)."""

    date: str = ""
    risk_score: float = 0.0
    score: float = 0.0

    model_config = ConfigDict(extra="allow")


class RiskComparisonPoint(BaseModel):
    """First/last scan comparison for the risk score chart."""

    date: str = ""
    risk_score: float = 0.0


class RiskResponse(_BaseViewResponse):
    """Full response shape for GET /api/v1/views/risk."""

    riskScore: float = 0.0
    riskLevel: str = "minimal"
    riskCategories: List[RiskCategory] = Field(default_factory=list)
    domainBreakdown: List[RiskCategory] = Field(default_factory=list)
    riskRegister: List[RiskRegisterItem] = Field(default_factory=list)
    scenarios: List[RiskScenario] = Field(default_factory=list)
    trendData: List[Dict[str, Any]] = Field(default_factory=list)
    activeScanTrend: List[RiskTrendPoint] = Field(default_factory=list)
    first: RiskComparisonPoint = Field(default_factory=RiskComparisonPoint)
    last: RiskComparisonPoint = Field(default_factory=RiskComparisonPoint)
    mitigationRoadmap: List[MitigationStep] = Field(default_factory=list)
    topAssets: List[TopAsset] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")
