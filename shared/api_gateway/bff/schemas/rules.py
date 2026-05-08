"""BFF contract schema — /rules view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext, FilterField, PageTab


class RulesKpi(BaseModel):
    model_config = ConfigDict(extra="allow")

    totalRules: int = 0
    total_rules: int = 0
    activeRules: int = 0
    builtInRules: int = 0
    customRules: int = 0


class RuleItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    rule_id: str = ""
    title: str = ""
    severity: str = ""
    provider: str = ""
    service: str = ""
    framework: str = ""
    status: str = ""
    is_custom: bool = False
    description: str = ""


class RuleTemplate(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = ""
    name: str = ""
    provider: str = ""
    framework: str = ""


class RulesResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    pageContext: Optional[PageContext] = None
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    rules: List[Any] = Field(default_factory=list)
    statistics: Dict[str, Any] = Field(default_factory=dict)
    templates: List[Any] = Field(default_factory=list)
    providerStatus: Dict[str, Any] = Field(default_factory=dict)
    kpi: RulesKpi = Field(default_factory=RulesKpi)
    byProvider: Dict[str, int] = Field(default_factory=dict)
    byService: Dict[str, int] = Field(default_factory=dict)
    byFramework: Dict[str, int] = Field(default_factory=dict)
    _meta: Optional[Dict[str, Any]] = None
