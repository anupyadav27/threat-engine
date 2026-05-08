"""Common Pydantic response schemas for BFF page views (JNY-13).

Strategy
--------
BFF page responses are deliberately heterogeneous (frontends reads dozens of
snake_case + camelCase fields, plus JSONB pass-through). To avoid breaking
existing UIs, the per-page response models defined here are **lenient**:

  - `model_config = ConfigDict(extra="allow")` so unknown/legacy fields pass
    through unchanged.
  - Only the structural envelope (`kpiGroups`, `pageContext`, `filterSchema`,
    primary list field) is validated.
  - A defense-in-depth `model_validator` walks the serialized payload and
    rejects any keys matching `credential|secret|raw_event` (mirrors the
    Phase B B3 pattern from `views/_schemas.py`).

This gives us:
  1. OpenAPI schema for every modeled endpoint (FastAPI `response_model=`).
  2. A safety net against accidental credential leakage via JSONB
     pass-through or upstream-engine field drift.
  3. No-op behavior change for the UI — the validators do not strip
     fields, they only block sensitive keys.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ── Sensitive-key scrubber (mirrors views/_schemas.py B3) ────────────────────
# Block actual credential-material field names.  Intentionally narrow:
#   BLOCKED  → credential_ref, credential_type, raw_event,
#              secret_access_key, secret_value, secret_key, secret_string,
#              credentials (exact word)
#   ALLOWED  → secrets_encrypted (boolean), secret_arn (ARN ref),
#              secret_name (display name), sm_entries (collection key)
# This avoids false-positive 500s on legitimate CSPM metadata fields while
# still rejecting any field that carries actual credential material.
_SENSITIVE_KEY_RE = re.compile(
    r"(^|_)(credential_ref|credential_type|raw_event"
    r"|secret_access_key|secret_value|secret_key|secret_string)(_|$)"
    r"|(^credentials?$)",
    re.IGNORECASE,
)


def _walk_keys(value: Any) -> List[str]:
    """Yield every string key found anywhere in a nested dict/list structure."""
    found: List[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                found.append(k)
            found.extend(_walk_keys(v))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk_keys(item))
    return found


# ── Common building blocks ───────────────────────────────────────────────────


class KpiItem(BaseModel):
    """Single KPI tile rendered by the UI."""

    model_config = ConfigDict(extra="allow")

    label: str
    value: Any
    suffix: Optional[str] = None


class KpiGroup(BaseModel):
    """Named group of KPI tiles (one card on the page)."""

    model_config = ConfigDict(extra="allow")

    title: str
    items: List[KpiItem] = Field(default_factory=list)


class PageTab(BaseModel):
    """Single tab in the page-context tab strip."""

    model_config = ConfigDict(extra="allow")

    id: str
    label: str
    count: Optional[int] = None


class PageContext(BaseModel):
    """Standard pageContext envelope produced by `_page_context.py` helpers."""

    model_config = ConfigDict(extra="allow")

    title: Optional[str] = None
    brief: Optional[str] = None
    details: List[str] = Field(default_factory=list)
    tabs: List[PageTab] = Field(default_factory=list)


class FilterField(BaseModel):
    """Wiz-style filter field descriptor (filterSchema entries)."""

    model_config = ConfigDict(extra="allow")

    key: str
    label: str
    type: str
    operators: List[str] = Field(default_factory=list)
    # values may include strings, booleans, numbers (e.g. severity tier ints,
    # boolean filters like "encrypted=true"). Stay permissive.
    values: Optional[List[Any]] = None


# ── Base view response with sensitive-key scrubber ───────────────────────────


class _BaseViewResponse(BaseModel):
    """Base for all BFF view responses.

    extra="allow" preserves the dozens of legacy / camelCase / snake_case
    fields each page returns without enumerating every one. The validator
    enforces credential-key denylist across the entire serialized output.
    """

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="after")
    def _scrub_sensitive_keys(self):
        dumped = self.model_dump(mode="python")
        for key in _walk_keys(dumped):
            if _SENSITIVE_KEY_RE.search(key):
                raise ValueError(
                    f"sensitive key '{key}' present in serialized "
                    f"{type(self).__name__}"
                )
        return self


# ── Per-page response models ─────────────────────────────────────────────────
# Each model declares only the structural envelope. Page-specific list fields
# are typed as List[Dict[str, Any]] so the legacy shape is preserved exactly.


class InventoryViewResponse(_BaseViewResponse):
    pageContext: PageContext
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    has_more: bool = False
    summary: Dict[str, Any] = Field(default_factory=dict)


class ThreatsViewResponse(_BaseViewResponse):
    pageContext: PageContext
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    scanMeta: Dict[str, Any] = Field(default_factory=dict)
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    threatFindings: List[Dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    trendData: List[Dict[str, Any]] = Field(default_factory=list)
    mitreMatrix: Dict[str, Any] = Field(default_factory=dict)
    attackChains: List[Dict[str, Any]] = Field(default_factory=list)
    threatIntel: List[Dict[str, Any]] = Field(default_factory=list)
    accountHeatmap: List[Dict[str, Any]] = Field(default_factory=list)
    kpi: Dict[str, Any] = Field(default_factory=dict)


class CiemViewResponse(_BaseViewResponse):
    # CIEM does not use pageContext / filterSchema today — keep them optional.
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    totalFindings: int = 0
    rulesTriggered: int = 0
    uniqueActors: int = 0
    uniqueResources: int = 0
    l2Findings: int = 0
    l3Findings: int = 0
    postureScore: int = 0
    severityBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    engineBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    ruleSourceBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    categoryBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    topCritical: List[Dict[str, Any]] = Field(default_factory=list)
    identities: List[Dict[str, Any]] = Field(default_factory=list)
    topRules: List[Dict[str, Any]] = Field(default_factory=list)
    logSources: List[Dict[str, Any]] = Field(default_factory=list)


class ComplianceViewResponse(_BaseViewResponse):
    pageContext: PageContext
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    frameworks: List[Dict[str, Any]] = Field(default_factory=list)
    failingControls: List[Dict[str, Any]] = Field(default_factory=list)
    trendData: List[Dict[str, Any]] = Field(default_factory=list)
    auditDeadlines: List[Dict[str, Any]] = Field(default_factory=list)
    exceptions: List[Dict[str, Any]] = Field(default_factory=list)
    accountMatrix: List[Dict[str, Any]] = Field(default_factory=list)


class IamViewResponse(_BaseViewResponse):
    pageContext: PageContext
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    findingsByModule: Dict[str, Any] = Field(default_factory=dict)
    byAccount: List[Dict[str, Any]] = Field(default_factory=list)
    byRegion: List[Dict[str, Any]] = Field(default_factory=list)
    identities: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    roles: List[Dict[str, Any]] = Field(default_factory=list)
    accessKeys: List[Dict[str, Any]] = Field(default_factory=list)
    privilegeEscalation: List[Dict[str, Any]] = Field(default_factory=list)
    serviceAccounts: List[Dict[str, Any]] = Field(default_factory=list)
    scanTrend: List[Dict[str, Any]] = Field(default_factory=list)


class DatasecViewResponse(_BaseViewResponse):
    pageContext: PageContext
    filterSchema: List[FilterField] = Field(default_factory=list)
    kpiGroups: List[KpiGroup] = Field(default_factory=list)
    catalog: List[Dict[str, Any]] = Field(default_factory=list)
    classifications: List[Dict[str, Any]] = Field(default_factory=list)
    lineage: Dict[str, Any] = Field(default_factory=dict)
    residency: List[Dict[str, Any]] = Field(default_factory=list)
    activity: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    dlp: List[Dict[str, Any]] = Field(default_factory=list)
    encryption: List[Dict[str, Any]] = Field(default_factory=list)
    accessMonitoring: List[Dict[str, Any]] = Field(default_factory=list)
    domainBreakdown: List[Dict[str, Any]] = Field(default_factory=list)
    scanTrend: List[Dict[str, Any]] = Field(default_factory=list)


__all__ = [
    "KpiItem",
    "KpiGroup",
    "PageTab",
    "PageContext",
    "FilterField",
    "InventoryViewResponse",
    "ThreatsViewResponse",
    "CiemViewResponse",
    "ComplianceViewResponse",
    "IamViewResponse",
    "DatasecViewResponse",
]
