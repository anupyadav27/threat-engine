"""BFF contract schema — /cwpp view."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from ._common import KpiGroup, PageContext, FilterField


class CWPPWorkload(BaseModel):
    model_config = ConfigDict(extra="allow")

    posture_score: Optional[float] = 0
    risk_band: str = ""
    status: str = ""
    summary: Dict[str, Any] = Field(default_factory=dict)


class CWPPContainers(BaseModel):
    model_config = ConfigDict(extra="allow")

    clusters: List[Any] = Field(default_factory=list)
    findings: List[Any] = Field(default_factory=list)
    domain_breakdown: List[Any] = Field(default_factory=list)


class CWPPImages(BaseModel):
    model_config = ConfigDict(extra="allow")

    inventory: List[Any] = Field(default_factory=list)
    findings: List[Any] = Field(default_factory=list)


class CWPPHosts(BaseModel):
    model_config = ConfigDict(extra="allow")

    scans: List[Any] = Field(default_factory=list)
    os_vulnerabilities: List[Any] = Field(default_factory=list)
    middleware_vulnerabilities: List[Any] = Field(default_factory=list)


class CWPPServerless(BaseModel):
    model_config = ConfigDict(extra="allow")

    functions: List[Any] = Field(default_factory=list)
    findings: List[Any] = Field(default_factory=list)


class CWPPRuntime(BaseModel):
    model_config = ConfigDict(extra="allow")

    findings: List[Any] = Field(default_factory=list)


class CWPPResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    pageContext: Optional[PageContext] = None
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    workload: CWPPWorkload = Field(default_factory=CWPPWorkload)
    containers: CWPPContainers = Field(default_factory=CWPPContainers)
    images: CWPPImages = Field(default_factory=CWPPImages)
    hosts: CWPPHosts = Field(default_factory=CWPPHosts)
    serverless: CWPPServerless = Field(default_factory=CWPPServerless)
    runtime: CWPPRuntime = Field(default_factory=CWPPRuntime)
    _meta: Optional[Dict[str, Any]] = None
