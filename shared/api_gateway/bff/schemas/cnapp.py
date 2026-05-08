"""BFF contract schema — /cnapp view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext, FilterField


class PillarItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    key: str = ""
    label: str = ""
    score: int = 0
    risk_band: str = ""
    findings: int = 0
    status: str = ""
    available: bool = True


class CNAPPDataWrapper(BaseModel):
    model_config = ConfigDict(extra="allow")

    pillars: List[Any] = Field(default_factory=list)
    pillars_ok: List[str] = Field(default_factory=list)
    pillars_unavailable: List[str] = Field(default_factory=list)
    cnapp_posture_score: Optional[float] = 0
    risk_band: str = ""
    raw: Optional[Any] = None


class CNAPPResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    pageContext: Optional[PageContext] = None
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    pillars: List[Any] = Field(default_factory=list)
    pillars_ok: List[str] = Field(default_factory=list)
    pillars_unavailable: List[str] = Field(default_factory=list)
    cnapp_posture_score: Optional[float] = 0
    risk_band: str = ""
    data: CNAPPDataWrapper = Field(default_factory=CNAPPDataWrapper)
    _meta: Optional[Dict[str, Any]] = None
