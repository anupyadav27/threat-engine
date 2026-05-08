"""BFF schema: /network-security view.

Source of truth: shared/api_gateway/bff/network_security.py return{}
Engine: network engine /api/v1/network-security/ui-data
UI: frontend/src/app/network-security/page.jsx

7 sub-tabs: overview, findings, security_groups, internet_exposure,
            topology, waf, domain_breakdown
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ._common import (
    BaseFindingItem,
    FilterField,
    KpiGroup,
    PageContext,
    _BaseViewResponse,
)

__all__ = [
    "NetworkFinding",
    "ModuleScoreItem",
    "ScanTrendPoint",
    "ScanComparisonPoint",
    "DonutSlice",
    "NetworkSecurityResponse",
]


class NetworkFinding(BaseFindingItem):
    """Network security finding with UI enrichment columns."""

    rule_id: str = ""
    title: str = ""
    module: str = ""
    network_layer: str = ""
    service: str = ""
    resource_name: str = ""
    open_to_internet: bool = False
    unrestricted: bool = False
    original: Dict[str, Any] = Field(default_factory=dict)
    meta: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class ModuleScoreItem(BaseModel):
    """One 7-layer module score card."""

    key: str
    label: str
    score: int = 0
    pass_: Optional[bool] = Field(default=None, alias="pass")

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class ScanTrendPoint(BaseModel):
    """Chart data point for the scan trend sparkline."""

    date: str = ""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    passRate: float = 0.0
    exposed_resources: int = 0
    waf_coverage: int = 0
    total: int = 0

    model_config = ConfigDict(extra="allow")


class ScanComparisonPoint(BaseModel):
    """First/last scan comparison object."""

    date: str = ""
    critical: int = 0
    high: int = 0
    total: int = 0


class DonutSlice(BaseModel):
    """Donut chart severity slice."""

    name: str
    value: int
    color: str


class NetworkSecurityResponse(_BaseViewResponse):
    """Full response shape for GET /api/v1/views/network-security."""

    findings: List[NetworkFinding] = Field(default_factory=list)
    security_groups: List[NetworkFinding] = Field(default_factory=list)
    internet_exposure: List[NetworkFinding] = Field(default_factory=list)
    topology: List[NetworkFinding] = Field(default_factory=list)
    topology_snapshots: List[Dict[str, Any]] = Field(default_factory=list)
    waf: List[NetworkFinding] = Field(default_factory=list)
    scanTrend: List[ScanTrendPoint] = Field(default_factory=list)
    activeScanTrend: List[ScanTrendPoint] = Field(default_factory=list)
    first: ScanComparisonPoint = Field(default_factory=ScanComparisonPoint)
    last: ScanComparisonPoint = Field(default_factory=ScanComparisonPoint)
    donutSlices: List[DonutSlice] = Field(default_factory=list)
    activeModuleScores: List[ModuleScoreItem] = Field(default_factory=list)
    domainBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    db: List[Dict[str, Any]] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")
