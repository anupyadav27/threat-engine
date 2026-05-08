"""BFF schema: /misconfig view.

Source of truth: shared/api_gateway/bff/misconfig.py return{}
Engine: threat engine /api/v1/threat/ui-data
UI: frontend/src/app/misconfig/page.jsx
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ._common import (
    BaseFindingItem,
    BFFErrorResponse,
    FilterField,
    KpiGroup,
    PageContext,
    _BaseViewResponse,
)

__all__ = [
    "MisconfigFinding",
    "HeatmapCell",
    "MisconfigKpi",
    "ScanTrendPoint",
    "MisconfigResponse",
]


class MisconfigFinding(BaseFindingItem):
    """Single misconfig finding row — superset of BaseFindingItem.

    normalize_check_finding() uses legacy field names (id, resource_arn,
    account, uppercase provider), so we give the inherited required fields
    defaults here; extra="allow" preserves the legacy keys for the UI.
    """

    # Override BaseFindingItem required fields — normalize_check_finding uses
    # 'id', 'resource_arn', and uppercase provider instead.
    finding_id: str = ""
    resource_uid: str = ""
    resource_type: str = ""
    provider: str = ""
    region: str = ""
    severity: str = "medium"
    status: str = "FAIL"

    rule_id: str = ""
    rule_name: str = ""
    description: str = ""
    remediation: Any = ""
    auto_remediable: bool = False
    age_days: Optional[int] = None
    sla_status: Optional[str] = None
    framework: str = ""
    environment: str = ""
    service: str = ""
    domain: str = ""
    posture_category: str = ""
    risk_score: Optional[int] = None
    compliance_frameworks: List[Any] = Field(default_factory=list)
    mitre_tactics: List[Any] = Field(default_factory=list)
    mitre_techniques: List[Any] = Field(default_factory=list)
    checked_fields: List[Any] = Field(default_factory=list)
    actual_values: List[Any] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class HeatmapCell(BaseModel):
    """One cell in the misconfig heatmap grid."""

    service: str
    severity: str
    count: int = 0

    model_config = ConfigDict(extra="allow")


class MisconfigKpi(BaseModel):
    """Legacy kpi object the UI severity cards read from data.kpi.*"""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    failed: int = 0
    passed: int = 0
    auto_remediable: int = 0
    avg_age: float = 0.0
    sla_breached: int = 0


class ScanTrendPoint(BaseModel):
    """One data point in the scanTrend sparkline."""

    date: str = ""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0
    passRate: Optional[float] = None

    model_config = ConfigDict(extra="allow")


class MisconfigResponse(_BaseViewResponse):
    """Full response shape for GET /api/v1/views/misconfig."""

    findings: List[MisconfigFinding] = Field(default_factory=list)
    heatmap: List[Dict[str, Any]] = Field(default_factory=list)
    quickWins: List[MisconfigFinding] = Field(default_factory=list)
    byService: Dict[str, int] = Field(default_factory=dict)
    kpi: MisconfigKpi = Field(default_factory=MisconfigKpi)
    scanTrend: List[ScanTrendPoint] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")
