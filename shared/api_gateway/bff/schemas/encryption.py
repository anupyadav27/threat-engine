"""BFF schema: /encryption view.

Source of truth: shared/api_gateway/bff/encryption.py return{}
Engine: encryption engine /api/v1/encryption/ui-data
        fallback: check engine domain=data_protection_and_privacy
UI: frontend/src/app/encryption/page.jsx
    → reads data.findings, data.keys, data.certificates, data.secrets,
      data.pageContext, data.kpiGroups, data.scanTrend, data.domainBreakdown
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext, FilterField, _BaseViewResponse

__all__ = [
    "EncryptionFinding",
    "EncryptionKpiItem",
    "ModuleScoreItem",
    "ScanTrendPoint",
    "ScanComparisonPoint",
    "DonutSlice",
    "EncryptionResponse",
]


class EncryptionFinding(BaseModel):
    """One row in the encryption findings / keys / certificates / secrets tables."""

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
    service: str = ""
    encryption_domain: str = ""
    encryption_status: str = ""
    # Key-specific columns
    key_id: str = ""
    algorithm: str = ""
    alias: str = ""
    key_type: str = ""
    key_algorithm: str = ""
    domain: str = ""
    last_rotated: str = ""
    rotation_enabled: bool = False
    rotation_compliant: Optional[bool] = False
    transit_enforced: Optional[bool] = False
    # Certificate-specific columns
    expires_at: str = ""
    days_until_expiry: Optional[int] = None
    issuer: str = ""
    # Priority columns
    priority: str = "medium"
    priority_score: int = 0
    original: Dict[str, Any] = Field(default_factory=dict)
    meta: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")


class EncryptionKpiItem(BaseModel):
    """Legacy flat kpis[] list item."""

    key: str
    label: str
    value: Any = 0
    suffix: str = ""


class ModuleScoreItem(BaseModel):
    """One encryption domain module score card."""

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
    unencrypted: int = 0
    expiring_certs: int = 0

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


class EncryptionResponse(_BaseViewResponse):
    """Full response for GET /api/v1/views/encryption."""

    overview: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[EncryptionFinding] = Field(default_factory=list)
    keys: List[Dict[str, Any]] = Field(default_factory=list)
    certificates: List[Dict[str, Any]] = Field(default_factory=list)
    sm_entries: List[Dict[str, Any]] = Field(default_factory=list)
    kpis: List[EncryptionKpiItem] = Field(default_factory=list)
    scanTrend: List[ScanTrendPoint] = Field(default_factory=list)
    activeScanTrend: List[ScanTrendPoint] = Field(default_factory=list)
    first: ScanComparisonPoint = Field(default_factory=ScanComparisonPoint)
    last: ScanComparisonPoint = Field(default_factory=ScanComparisonPoint)
    donutSlices: List[DonutSlice] = Field(default_factory=list)
    activeModuleScores: List[ModuleScoreItem] = Field(default_factory=list)
    domainBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    db: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")
