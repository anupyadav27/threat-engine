"""BFF contract schema — /reports view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ._common import PageTab


class ReportsKpi(BaseModel):
    model_config = ConfigDict(extra="allow")

    totalReports: int = 0
    scheduledCount: int = 0
    byFormat: Dict[str, int] = Field(default_factory=dict)
    byTemplate: Dict[str, int] = Field(default_factory=dict)


class ReportItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    report_id: str = ""
    name: str = ""
    framework: str = ""
    date: str = ""
    assessed: str = ""
    attestedBy: str = ""
    auditPeriod: str = ""
    collected: str = ""
    format: str = ""
    status: str = ""


class ScheduledReport(BaseModel):
    model_config = ConfigDict(extra="allow")

    schedule_id: str = ""
    name: str = ""
    frequency: str = ""
    lastRun: str = ""
    nextRun: str = ""
    recipients: List[str] = Field(default_factory=list)


class ReportTemplate(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = ""
    name: str = ""
    desc: str = ""
    format: str = "PDF"


class ReportsResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    kpi: ReportsKpi = Field(default_factory=ReportsKpi)
    reports: List[Any] = Field(default_factory=list)
    scheduled: List[Any] = Field(default_factory=list)
    templates: List[ReportTemplate] = Field(default_factory=list)
    tabs: List[PageTab] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None
