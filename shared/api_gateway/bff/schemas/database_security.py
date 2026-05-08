"""BFF schema: /database-security view.

Source of truth: shared/api_gateway/bff/database_security.py return{}
Engine: dbsec engine /api/v1/database-security/ui-data
        fallback: check engine domain=database_security
UI: frontend/src/app/database-security/page.jsx
    → reads data.databases, data.findings, data.domain_scores,
      data.pageContext, data.kpiGroups, data.scanTrend, data.domainBreakdown

Six tabs: overview, inventory (databases), findings, access_control,
          encryption, audit_logging
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext, FilterField, _BaseViewResponse

__all__ = [
    "DatabaseItem",
    "DatabaseFinding",
    "ModuleScoreItem",
    "ScanTrendPoint",
    "ScanComparisonPoint",
    "DonutSlice",
    "DatabaseSecurityResponse",
]


class DatabaseItem(BaseModel):
    """One row in the database inventory table."""

    name: str = ""
    db_engine: str = ""
    db_service: str = ""
    provider: str = ""
    region: str = ""
    account_id: str = ""
    publicly_accessible: bool = False
    encrypted: bool = False
    multi_az: bool = False
    posture_score: int = 0
    status: str = ""

    model_config = ConfigDict(extra="allow")


class DatabaseFinding(BaseModel):
    """One database security finding row."""

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
    rule_id: str = ""
    db_service: str = ""
    db_engine: str = ""
    security_domain: str = ""
    original: Dict[str, Any] = Field(default_factory=dict)
    meta: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class ModuleScoreItem(BaseModel):
    """One database security domain score card."""

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


class DatabaseSecurityResponse(_BaseViewResponse):
    """Full response for GET /api/v1/views/database-security."""

    databases: List[DatabaseItem] = Field(default_factory=list)
    findings: List[DatabaseFinding] = Field(default_factory=list)
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
