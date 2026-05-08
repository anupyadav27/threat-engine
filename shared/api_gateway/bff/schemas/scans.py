"""BFF contract schema — /scans view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext


class ScanRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_run_id: str = ""
    status: str = ""
    provider: str = ""
    account_id: str = ""
    region: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration: str = ""
    total_resources: int = 0
    total_findings: int = 0
    trigger: str = ""
    schedule: str = ""


class ScanStats(BaseModel):
    model_config = ConfigDict(extra="allow")

    total: int = 0
    completed: int = 0
    running: int = 0
    failed: int = 0


class ScansResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    pageContext: Optional[PageContext] = None
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    scans: List[Any] = Field(default_factory=list)
    runs: List[Any] = Field(default_factory=list)
    scheduled: List[Any] = Field(default_factory=list)
    schedules: List[Any] = Field(default_factory=list)
    accounts: List[Any] = Field(default_factory=list)
    coverageByProvider: Dict[str, Any] = Field(default_factory=dict)
    stats: ScanStats = Field(default_factory=ScanStats)
    total: int = 0
    _meta: Optional[Dict[str, Any]] = None
