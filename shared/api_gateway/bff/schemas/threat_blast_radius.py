"""BFF contract schema — /threats/blast-radius view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class BlastRadiusKpi(BaseModel):
    model_config = ConfigDict(extra="allow")

    totalDetections: int = 0
    detectionsWithBlast: int = 0
    totalReachable: int = 0
    internetExposed: int = 0


class BlastRadiusItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    detectionId: str = ""
    resourceUid: str = ""
    resourceName: str = ""
    resourceType: str = ""
    provider: str = ""
    accountId: str = ""
    region: str = ""
    severity: str = ""
    riskScore: int = 0
    verdict: str = ""
    reachableCount: int = 0
    maxHops: int = 0
    reachableResources: List[Any] = Field(default_factory=list)
    pathEdges: List[Any] = Field(default_factory=list)
    isInternetReachable: bool = False
    ruleName: str = ""


class ThreatBlastRadiusResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    kpi: BlastRadiusKpi = Field(default_factory=BlastRadiusKpi)
    blastItems: List[BlastRadiusItem] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None
