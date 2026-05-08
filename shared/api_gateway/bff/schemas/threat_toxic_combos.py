"""BFF contract schema — /threats/toxic-combos view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ToxicComboKpi(BaseModel):
    model_config = ConfigDict(extra="allow")

    total: int = 0
    critical: int = 0
    high: int = 0
    avgThreatsPerCombo: float = 0.0


class ToxicComboItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    combo_id: str = ""
    severity: str = ""
    risk_score: int = 0
    resources: List[Any] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    description: str = ""


class ThreatToxicCombosResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    kpi: ToxicComboKpi = Field(default_factory=ToxicComboKpi)
    toxicCombinations: List[Any] = Field(default_factory=list)
    coOccurrenceMatrix: Dict[str, Any] = Field(default_factory=dict)
    _meta: Optional[Dict[str, Any]] = None
