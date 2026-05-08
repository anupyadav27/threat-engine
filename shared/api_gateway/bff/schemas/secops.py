"""BFF schema: /secops view (Code Security — SAST + DAST).

Source of truth: shared/api_gateway/bff/secops.py return{}
Engine: secops engine /api/v1/secops/sast/scans, /api/v1/secops/dast/scans
UI: frontend/src/app/secops/page.jsx
    → reads bff.sastScans, bff.dastScans (SCA handled separately via direct call)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup

__all__ = [
    "ScanRecord",
    "SecopsAggregate",
    "SecOpsTrendPoint",
    "SecopsResponse",
]


class ScanRecord(BaseModel):
    """One normalised SAST or DAST scan record."""

    scan_id: str = ""
    source: str = ""
    project: str = ""
    language: str = ""
    status: str = "unknown"
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total_findings: int = 0
    scan_timestamp: str = ""
    duration_s: int = 0

    model_config = ConfigDict(extra="allow")


class SecopsAggregate(BaseModel):
    """Aggregate KPI computed from all completed scans (summary key)."""

    totalScans: int = 0
    completedScans: int = 0
    totalFindings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    riskScore: float = 0.0


class SecOpsTrendPoint(BaseModel):
    """One chart data point in the scan trend sparkline."""

    date: str = ""
    source: str = ""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    pass_rate: float = 0.0

    model_config = ConfigDict(extra="allow")


class SecopsResponse(BaseModel):
    """Full response for GET /api/v1/views/secops.

    No _BaseViewResponse — this view has no pageContext or filterSchema tabs.
    """

    sastScans: List[ScanRecord] = Field(default_factory=list)
    dastScans: List[ScanRecord] = Field(default_factory=list)
    summary: SecopsAggregate = Field(default_factory=SecopsAggregate)
    scanTrend: List[SecOpsTrendPoint] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")
