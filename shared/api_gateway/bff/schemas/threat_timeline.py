"""BFF contract schema — /threats/timeline view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TimelineEventKpi(BaseModel):
    model_config = ConfigDict(extra="allow")

    totalEvents: int = 0
    detected: int = 0
    resolved: int = 0
    avgResponseTime: str = "—"
    openInvestigations: int = 0


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: str = ""
    title: str = ""
    severity: str = ""
    status: str = ""
    timestamp: str = ""
    resource_uid: str = ""
    resource_type: str = ""
    provider: str = ""
    account_id: str = ""
    region: str = ""
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class ThreatTimelineResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    events: List[Any] = Field(default_factory=list)
    kpi: TimelineEventKpi = Field(default_factory=TimelineEventKpi)
    _meta: Optional[Dict[str, Any]] = None
