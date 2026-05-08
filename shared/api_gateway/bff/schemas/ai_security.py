"""BFF contract schema — /ai-security view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext, FilterField


class AICoverageMetrics(BaseModel):
    model_config = ConfigDict(extra="allow")

    vpc_isolation_pct: int = 0
    encryption_rest_pct: int = 0
    encryption_transit_pct: int = 0
    model_card_pct: int = 0
    monitoring_pct: int = 0
    guardrails_pct: int = 0


class AICoverageItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    key: str = ""
    label: str = ""
    pct: int = 0


class AIModuleScore(BaseModel):
    model_config = ConfigDict(extra="allow")

    key: str = ""
    label: str = ""
    score: int = 0
    pass_: bool = Field(False, alias="pass")

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class AIShadowAI(BaseModel):
    model_config = ConfigDict(extra="allow")

    count: int = 0
    items: List[Any] = Field(default_factory=list)


class AISecurityResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    pageContext: Optional[PageContext] = None
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    modules: List[Any] = Field(default_factory=list)
    activeModuleScores: List[Any] = Field(default_factory=list)
    coverage: AICoverageMetrics = Field(default_factory=AICoverageMetrics)
    coverageItems: List[AICoverageItem] = Field(default_factory=list)
    inventory: List[Any] = Field(default_factory=list)
    shadowAi: AIShadowAI = Field(default_factory=AIShadowAI)
    findings: List[Any] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None
