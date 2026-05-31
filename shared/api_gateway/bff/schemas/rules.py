"""BFF contract schema — /rules view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RuleSummary(BaseModel):
    model_config = ConfigDict(extra="allow")

    total:      int = 0
    active:     int = 0
    suppressed: int = 0
    by_type:    Dict[str, int] = Field(default_factory=dict)


class RuleTemplate(BaseModel):
    model_config = ConfigDict(extra="allow")

    id:          str = ""
    name:        str = ""
    provider:    str = ""
    framework:   str = ""
    description: str = ""


class RulesKpi(BaseModel):
    """Top-level KPI counters for the rules library view."""

    model_config = ConfigDict(extra="allow")

    total:      int = 0
    active:     int = 0
    suppressed: int = 0
    custom:     int = 0
    by_type:    Dict[str, int] = Field(default_factory=dict)


class RulesResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    rules:     List[Any]          = Field(default_factory=list)
    templates: List[Any]          = Field(default_factory=list)
    summary:   RuleSummary        = Field(default_factory=RuleSummary)
    kpi:       RulesKpi           = Field(default_factory=RulesKpi)
    _meta:     Optional[Dict[str, Any]] = None
