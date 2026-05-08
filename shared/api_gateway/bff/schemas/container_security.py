"""BFF schema: /container-security view.

Source of truth: shared/api_gateway/bff/container_security.py return{}
Engine: container_sec engine /api/v1/container-security/ui-data
        fallback: check engine domain=container_and_kubernetes_security
UI: frontend/src/app/container-security/page.jsx
    → reads data.clusters, data.findings, data.domain_scores,
      data.pageContext, data.kpiGroups, data.scanTrend, data.domainBreakdown

Six tabs: overview, inventory (clusters), findings, cluster_security,
          image_security, rbac
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext, FilterField, _BaseViewResponse

__all__ = [
    "ClusterItem",
    "ContainerFinding",
    "ModuleScoreItem",
    "ScanTrendPoint",
    "ScanComparisonPoint",
    "DonutSlice",
    "ContainerSecurityResponse",
]


class ClusterItem(BaseModel):
    """One row in the cluster inventory table."""

    name: str = ""
    provider: str = ""
    region: str = ""
    account_id: str = ""
    version: str = ""
    node_count: int = 0
    pod_count: int = 0
    posture_score: int = 0
    risk_score: int = 0
    endpoint_public: bool = False
    logging_enabled: bool = False
    etcd_encrypted: bool = False
    status: str = ""

    model_config = ConfigDict(extra="allow")


class ContainerFinding(BaseModel):
    """One container / Kubernetes security finding row."""

    finding_id: str = ""
    resource_uid: str = ""
    resource_name: str = ""
    resource_type: str = ""
    provider: str = ""
    region: str = ""
    account_id: str = ""
    severity: str = "medium"
    status: str = "FAIL"
    title: str = ""
    rule_id: Optional[str] = ""
    cluster_name: str = ""
    container_service: str = ""
    security_domain: str = ""
    original: Dict[str, Any] = Field(default_factory=dict)
    meta: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class ModuleScoreItem(BaseModel):
    """One container security domain score card."""

    key: str
    label: str
    score: int = 0
    pass_: Optional[bool] = Field(default=None, alias="pass")

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class ScanTrendPoint(BaseModel):
    date: str = ""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    passRate: float = 0.0
    total: int = 0

    model_config = ConfigDict(extra="allow")


class ScanComparisonPoint(BaseModel):
    date: Any = ""
    critical: int = 0
    high: int = 0
    total: int = 0


class DonutSlice(BaseModel):
    name: str
    value: int
    color: str


class ContainerSecurityResponse(_BaseViewResponse):
    """Full response for GET /api/v1/views/container-security."""

    clusters: List[ClusterItem] = Field(default_factory=list)
    findings: List[ContainerFinding] = Field(default_factory=list)
    domain_scores: Dict[str, int] = Field(default_factory=dict)
    domainBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    db: List[Dict[str, Any]] = Field(default_factory=list)
    scanTrend: List[ScanTrendPoint] = Field(default_factory=list)
    activeScanTrend: List[ScanTrendPoint] = Field(default_factory=list)
    first: ScanComparisonPoint = Field(default_factory=ScanComparisonPoint)
    last: ScanComparisonPoint = Field(default_factory=ScanComparisonPoint)
    donutSlices: List[DonutSlice] = Field(default_factory=list)
    activeModuleScores: List[ModuleScoreItem] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")
