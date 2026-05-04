# DI-09: BFF — TypedDict Schemas for All BFF View Responses

## Track
Track 2 — BFF Contract Audit

## Priority
P1 — foundational for DI-10 (field mismatch fixes)

## Story
As a backend engineer, I need TypedDict schema definitions for each BFF view's response, so that field name mismatches between BFF output and frontend consumption are caught at review time (and eventually by mypy) before they reach production.

## Background

Today the BFF returns untyped dicts. If a view returns `risk_score` but the frontend reads `riskScore`, the chart silently shows zero. TypedDicts make the contract explicit and reviewable.

This story creates the schema file. Field mismatch FIXES are in DI-10.

## File to Create

`/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/schemas/__init__.py`
`/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/schemas/views.py`

## Implementation

`schemas/views.py` (excerpt — implement ALL views):

```python
"""
TypedDict schemas for BFF view responses.

Each TypedDict represents the contract between a BFF view handler
and the frontend component that reads it. Field names MUST match
what the React component expects (camelCase for UI-facing views).

Rules:
- All field names are camelCase (matching React convention)
- All optional fields use Optional[T]
- Nested objects have their own TypedDict
- Lists of items use List[T]
"""
from typing import TypedDict, Optional, List, Dict, Any


# ── Shared ──────────────────────────────────────────────────────────────────

class KpiItem(TypedDict):
    label: str
    value: Any
    suffix: Optional[str]
    change: Optional[float]

class KpiGroup(TypedDict):
    title: str
    items: List[KpiItem]

class ScanMeta(TypedDict):
    scanRunId: str
    latestDetection: str
    dataScope: str


# ── Dashboard ────────────────────────────────────────────────────────────────

class PostureHero(TypedDict):
    score: int
    label: str
    change: Optional[float]

class CloudHealthEntry(TypedDict):
    provider: str
    score: int
    critical: int
    high: int
    medium: int
    low: int

class DashboardView(TypedDict):
    kpiGroups: List[KpiGroup]
    postureHero: PostureHero
    cloudHealth: List[CloudHealthEntry]
    trendData: List[Dict[str, Any]]
    topRiskyResources: List[Dict[str, Any]]
    complianceFrameworks: List[Dict[str, Any]]
    criticalActions: List[Dict[str, Any]]
    scanMeta: ScanMeta


# ── Threats ──────────────────────────────────────────────────────────────────

class ThreatItem(TypedDict):
    id: str
    title: str
    severity: str                # "critical" | "high" | "medium" | "low"
    riskScore: int               # 0-100 (NOTE: not risk_score)
    status: str
    resourceType: str
    resourceUid: str
    account: str
    region: str
    provider: str
    mitreTactics: List[str]      # NOTE: not mitre_tactics
    mitreTechiqueIds: List[str]
    detectedAt: str              # ISO timestamp
    contributingFindings: List[Dict[str, Any]]
    hasAttackPath: bool
    isInternetExposed: bool

class MitreMatrixEntry(TypedDict):
    id: str
    name: str
    severity: str
    count: int

class ThreatsView(TypedDict):
    threats: List[ThreatItem]
    total: int
    kpiGroups: List[KpiGroup]
    mitreMatrix: Dict[str, List[MitreMatrixEntry]]
    attackChains: List[Dict[str, Any]]
    trendData: List[Dict[str, Any]]
    accountHeatmap: List[Dict[str, Any]]
    scanMeta: ScanMeta


# ── Compliance ───────────────────────────────────────────────────────────────

class FrameworkScore(TypedDict):
    frameworkId: str
    frameworkName: str
    score: int                   # 0-100
    passCount: int
    failCount: int
    totalControls: int

class ComplianceView(TypedDict):
    frameworks: List[FrameworkScore]
    overallScore: int
    trendData: List[Dict[str, Any]]
    controlBreakdown: List[Dict[str, Any]]


# ── Inventory ────────────────────────────────────────────────────────────────

class ResourceItem(TypedDict):
    resourceUid: str
    resourceType: str
    provider: str
    accountId: str
    region: str
    tags: Dict[str, str]
    firstSeen: str
    lastSeen: str

class InventoryView(TypedDict):
    total: int
    resources: List[ResourceItem]
    byProvider: Dict[str, int]
    byRegion: Dict[str, int]
    byResourceType: Dict[str, int]
    driftCount: int


# ── IAM ──────────────────────────────────────────────────────────────────────

class IamView(TypedDict):
    total: int
    findings: List[Dict[str, Any]]
    byCategory: Dict[str, int]
    highPrivilegeCount: int
    unusedPermissionsCount: int


# ── Risk ─────────────────────────────────────────────────────────────────────

class RiskScenario(TypedDict):
    scenarioId: str
    title: str
    riskScore: int               # NOTE: riskScore (camelCase)
    severity: str
    resourceCount: int
    blastRadius: int

class RiskView(TypedDict):
    overallRiskScore: int
    scenarios: List[RiskScenario]
    topRiskyResources: List[Dict[str, Any]]
    riskByCategory: Dict[str, int]


# ── (Add remaining views: datasec, network, ciem, etc.) ────────────────────
# Pattern: create one TypedDict per view, naming fields in camelCase.
```

## Field Name Convention Audit

The following mismatches have been identified between BFF output and frontend consumption.
They are DOCUMENTED here; the actual fixes are in DI-10.

| View | BFF returns | Frontend reads | Status |
|------|-------------|----------------|--------|
| threats | `risk_score` (from engine) | `riskScore` | MISMATCH |
| threats | `mitre_tactics` | `mitreTactics` | MISMATCH |
| threats | `resource_type` | `resourceType` | MISMATCH |
| risk | `risk_score` | `riskScore` | MISMATCH |
| compliance | `framework_name` | `frameworkName` | MISMATCH |
| inventory | `resource_uid` | `resourceUid` | MISMATCH |

## Acceptance Criteria

- [ ] `schemas/views.py` file created with TypedDicts for all 15+ views
- [ ] All TypedDict field names are camelCase (matching React convention)
- [ ] `DashboardView`, `ThreatsView`, `ComplianceView`, `InventoryView`, `IamView`, `RiskView` all defined
- [ ] Mismatch table in this story is reconciled: every field in TypedDict matches what the React component actually reads
- [ ] `mypy` runs without errors on the schemas file (at minimum `--ignore-missing-imports`)

## Research Task (before coding)

Before finalizing TypedDict field names, do a targeted audit for each view:
1. Open the React page component (e.g. `/threats/page.jsx`)
2. Find every `data.X` or `data?.X` read
3. The field name used in JSX is the TypedDict field name
4. Compare against what the BFF currently returns (read the BFF handler)
5. Note mismatches for DI-10

## Definition of Done
- Schemas file committed
- Field names match React reads (verified by reading JSX)
- Mismatch table completed and handed off to DI-10
