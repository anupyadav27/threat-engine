"""BFF contract schema — /threats/graph view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class GraphKpi(BaseModel):
    model_config = ConfigDict(extra="allow")

    nodes: int = 0
    edges: int = 0
    avgRisk: float = 0.0
    internetExposed: int = 0
    pathEdges: int = 0
    associationEdges: int = 0
    orcaPaths: int = 0


class GraphNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    uid: str = ""
    label: str = ""
    type: str = ""
    severity: str = ""
    risk_score: int = 0
    finding_count: int = 0
    is_internet_reachable: bool = False


class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str = ""
    target: str = ""
    edge_kind: str = ""
    label: str = ""


class GraphCapabilities(BaseModel):
    model_config = ConfigDict(extra="allow")

    has_cve_nodes: bool = False


class ThreatGraphResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    kpi: GraphKpi = Field(default_factory=GraphKpi)
    nodes: List[Any] = Field(default_factory=list)
    links: List[Any] = Field(default_factory=list)
    orca_paths: List[Any] = Field(default_factory=list)
    graph_capabilities: GraphCapabilities = Field(default_factory=GraphCapabilities)
    filterSchema: List[Any] = Field(default_factory=list)
    _meta: Optional[Dict[str, Any]] = None


class NodeSecurityResponse(BaseModel):
    """Shape for /threats/graph/node-security/{resource_uid}."""
    model_config = ConfigDict(extra="allow")

    configProperties: List[Any] = Field(default_factory=list)
    failCount: int = 0
    cves: List[Any] = Field(default_factory=list)
    cveCount: int = 0
    criticalCveCount: int = 0
    node_uid: str = ""
