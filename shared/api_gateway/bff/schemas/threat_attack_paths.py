"""BFF contract schema — /threats/attack-paths view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AttackPathStep(BaseModel):
    model_config = ConfigDict(extra="allow")

    step: int = 0
    action: str = ""
    resource: str = ""
    resourceType: str = ""
    severity: str = ""


class AttackPathNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    uid: str = ""
    label: str = ""
    type: str = ""
    severity: str = ""
    findingCount: int = 0
    threatCount: int = 0


class AttackPathItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = ""
    title: str = ""
    description: str = ""
    chainType: str = ""
    severity: str = ""
    pathScore: int = 0
    depth: int = 0
    entryPoint: str = ""
    entryPointName: str = ""
    target: str = ""
    targetName: str = ""
    targetCategory: str = ""
    steps: List[Any] = Field(default_factory=list)
    nodes: List[Any] = Field(default_factory=list)
    detectionId: str = ""
    resourceUid: str = ""
    resourceType: str = ""
    riskScore: int = 0
    provider: str = ""
    accountId: str = ""
    region: str = ""
    isInternetReachable: bool = False
    mitreTechniques: List[str] = Field(default_factory=list)
    source: str = ""


class AttackPathKpi(BaseModel):
    model_config = ConfigDict(extra="allow")

    total: int = 0
    critical: int = 0
    high: int = 0
    internetReachable: int = 0


class ThreatAttackPathsResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    kpi: AttackPathKpi = Field(default_factory=AttackPathKpi)
    chainTypes: Dict[str, int] = Field(default_factory=dict)
    attackPaths: List[AttackPathItem] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None
