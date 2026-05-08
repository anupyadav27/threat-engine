"""BFF schema: /threat-command-room view.

Source of truth: shared/api_gateway/bff/threat_command_room.py return{}
Engine: threat engine /api/v1/threat/ui-data
UI: frontend/src/components/domain/threats/CommandRoom.jsx
    → reads data.pulse_stats, data.scenarios, data.total, data.trendPoints
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ._common import _BaseViewResponse

__all__ = [
    "MitreTechnique",
    "ThreatScenario",
    "PulseStats",
    "TrendPoint",
    "ThreatCommandRoomResponse",
]


class MitreTechnique(BaseModel):
    """Normalised MITRE ATT&CK technique reference."""

    id: str
    name: str = ""


class ThreatScenario(BaseModel):
    """One threat detection scenario surfaced in the Command Room."""

    scenario_id: str = ""
    title: str = ""
    severity: str = "medium"
    risk_score: int = 0
    resource_uid: str = ""
    resource_name: str = ""
    resource_type: str = ""
    csp: str = ""
    region: str = ""
    account_id: str = ""
    signal_types: List[str] = Field(default_factory=list)
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
    setup_summary: str = ""
    last_scan_age: str = ""
    delta_since_last_scan: int = 0
    first_seen_at: str = ""
    attack_chain: List[Any] = Field(default_factory=list)
    top_findings: List[Any] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class PulseStats(BaseModel):
    """Header KPI pulse block for the Command Room hero panel."""

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    composite_score: int = 0
    delta_count: int = 0
    delta_direction: str = "flat"
    new_today: int = 0
    last_scan_at: Optional[str] = None
    last_scan_age_human: Optional[str] = None
    last_scan_age: Optional[str] = None
    scan_status: str = "completed"


class TrendPoint(BaseModel):
    """One data point in the threat trend sparkline."""

    date: str = ""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    risk_score: int = 0
    total: int = 0
    passRate: float = 0.0
    tactics: List[Any] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class ThreatCommandRoomResponse(BaseModel):
    """Full response shape for GET /api/v1/views/threat-command-room.

    No _BaseViewResponse because this view has no filterSchema or pageContext tabs.
    """

    pulse_stats: PulseStats = Field(default_factory=PulseStats)
    scenarios: List[ThreatScenario] = Field(default_factory=list)
    total: int = 0
    count: int = 0
    scan_run_id: str = ""
    trendPoints: List[TrendPoint] = Field(default_factory=list)
    brief: str = ""
    # Flat aliases for UI backward-compat
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    risk_score: int = 0
    composite_score: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    new_today: int = 0
    delta_count: int = 0
    delta_direction: str = "flat"
    last_scan_at: Optional[str] = None
    last_scan_age: Optional[str] = None
    last_scan_age_human: Optional[str] = None
    scan_status: str = "completed"
    finding_id: str = ""
    scenario_id: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)
    _meta: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")
