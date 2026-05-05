# JNY-06 — Universal Finding BFF — Design Handoff

## 1. Endpoint contract

| Field | Value |
|---|---|
| Method/URL | `GET /api/v1/views/finding/{engine}/{id}` |
| Module | `shared/api_gateway/bff/views/finding_detail.py` (new) |
| Engine map | `shared/api_gateway/bff/views/_finding_engine_map.py` (new) |
| Auth | `Depends(require_permission(_PERM_BY_ENGINE[engine]))` resolved per-engine |
| Tenant | `tenant_id = resolve_tenant_id(request)` from `X-Auth-Context` (NEVER query param — DI-05/06) |
| Path validation | `engine: Literal[...]` enum; `id: constr(min_length=1, max_length=128, regex=r"^[A-Za-z0-9._:/\-]+$")` |
| Query params | none |
| OpenAPI | `response_model=FindingDetailResponse` |
| Performance | p50 < 200ms; p95 < 800ms; story cap p95 < 2.5s |

### Strategy: DB-direct, not HTTP fan-out for Tab 1

The story explicitly mandates "BFF must read 11 different finding tables using ONLY standard columns." We pick **direct DB reads via `shared/common/db_connections.py`** for Tab 1. Reasons:

1. Standard-column contract enforced at schema level — no HTTP shape drift.
2. Only 2/11 engines have a singular HTTP detail endpoint today (`threat`, `ciem`). Spinning up 9 new engine endpoints just to read a row by PK is wasteful; BFF already owns DB credentials (precedent: `asset_context.py`).
3. Tabs 3 (related findings via cross-engine `resource_uid`), 4 (compliance via `rule_control_mapping`), 5 (remediation via `rule_metadata`) are all natural DB-shape queries.
4. Tab 2 (resource context) handled entirely by frontend calling existing `/api/v1/asset-context/{uid}` separately — BFF returns `resourceContext: null`.

## 2. Per-engine matrix

Verified by grepping each engine's `api_server.py`. Singular endpoint = `GET .../findings/{id}`.

| # | Slug | DB conn helper (exists) | Table | Singular HTTP endpoint? | Action |
|---|---|---|---|---|---|
| 1 | `check` | `get_check_conn` | `check_findings` | NO (list only `/api/v1/check/findings`) | DB-direct |
| 2 | `threat` | `get_threat_conn` | `threat_findings` / `threat_detections` | YES — `GET /api/v1/threat/{threat_id}` | DB-direct (uniformity) |
| 3 | `iam` | `get_iam_conn` | `iam_findings` | NO | DB-direct |
| 4 | `network` | `get_network_conn` | `network_findings` | NO | DB-direct |
| 5 | `datasec` | `get_datasec_conn` | `datasec_findings` | NO | DB-direct |
| 6 | `encryption` | `get_encryption_conn` | `encryption_findings` | NO (only by-resource list) | DB-direct |
| 7 | `container` | `get_container_sec_conn` | `container_sec_findings` | NO | DB-direct |
| 8 | `dbsec` | `get_dbsec_conn` | `dbsec_findings` | NO | DB-direct |
| 9 | `ai_security` | `get_ai_security_conn` | `ai_security_findings` | NO | DB-direct |
| 10 | `ciem` | `get_ciem_conn` | `ciem_findings` | YES — `GET /api/v1/ciem/findings/{finding_id}` | DB-direct (uniformity) |
| 11 | `secops` | **MISSING** | (TBD — likely `secops_findings`) | NO (only `/api/v1/secops/scan/{scan_id}/findings`) | **GAP — STORY-ENG-secops-finding-table** |

**Engines with detail-endpoint: 2/11. Engines needing new endpoint: 0** (we read DB directly; secops needs a DB conn helper + table confirmation, not an HTTP endpoint).

## 3. Pydantic models (Layer 2 contract)

```python
## CP-2 spec amendments (closes B1/B2/B3/B4)

- **B1 closed:** Canonical engine slugs are LONG (matches K8s service names + JNY-05 §1):
  `["check","threat","iam","network-security","datasec","encryption","container-security","dbsec","ai-security","ciem","secops"]`
  `_finding_engine_map.py` maps these to DB conn helpers. Short-slug aliases (`network`, `container`, `ai`) are NOT accepted at the URL/BFF boundary.

- **B2 closed:** Add a NEW BFF write endpoint `PATCH /api/v1/views/finding/{engine}/{id}/status` to JNY-06 scope. UI calls this; BFF calls per-engine writer functions; audit-log emission centralized in BFF. Status mutation NEVER bypasses BFF. JNY-05 §2 action-bar status button calls this BFF endpoint, not engine directly.

- **B3 closed:** Add `tests/bff/test_finding_response_shape.py` with:
  ```python
  MANDATORY_14 = {"tenantId","scanRunId","credentialRef","credentialType","findingId",
                  "accountId","provider","region","resourceUid","resourceType",
                  "severity","status","firstSeenAt","lastSeenAt"}
  def test_standard_columns_contains_mandatory_14():
      assert set(StandardColumns.model_fields) >= MANDATORY_14
  ```
  And add Pydantic `@model_validator(mode='after')` on `FindingDetailResponse` rejecting any serialized output containing keys matching `/credential|secret|raw_event/i` (defense-in-depth on top of `exclude=True`).

- **B4 closed:** `secops` is explicitly deferred to Phase C. JNY-06 returns 501 with `{"detail":"engine 'secops' not yet supported","story_ref":"STORY-ENG-SECOPS-FINDING-TABLE"}`. JNY-07 PivotLink hides `engine='secops'` finding pivots in Phase B (renders muted plain text). File `STORY-ENG-SECOPS-FINDING-TABLE` as separate spin-off; do NOT block Phase B on it.

---

EngineSlug = Literal["check","threat","iam","network-security","datasec","encryption",
                     "container-security","dbsec","ai-security","ciem","secops"]

class StandardColumns(BaseModel):
    tenantId: str
    scanRunId: Optional[str]
    credentialRef: Optional[str] = Field(None, exclude=True)   # NEVER echoed
    credentialType: Optional[str] = Field(None, exclude=True)  # NEVER echoed
    findingId: str
    accountId: Optional[str]; provider: Optional[str]; region: Optional[str]
    resourceUid: Optional[str]; resourceType: Optional[str]
    severity: Optional[str]; status: Optional[str]
    firstSeenAt: Optional[datetime]; lastSeenAt: Optional[datetime]

class FindingHeader(BaseModel):
    findingId: str; engine: EngineSlug
    ruleId: Optional[str]; severity: Optional[str]; status: Optional[str]
    title: Optional[str]; description: Optional[str]
    resourceUid: Optional[str]; resourceType: Optional[str]; resourceName: Optional[str]
    provider: Optional[str]; accountId: Optional[str]; region: Optional[str]
    firstSeenAt: Optional[datetime]; lastSeenAt: Optional[datetime]
    riskScore: Optional[int] = None
    standardColumns: StandardColumns
    findingData: dict = Field(default_factory=dict)   # JSONB pass-through

class RelatedFinding(BaseModel):
    engine: EngineSlug; findingId: str; severity: Optional[str]
    ruleId: Optional[str]; title: Optional[str]; status: Optional[str]

class RelatedFindingsBlock(BaseModel):
    available: bool                              # false when ALL engines failed
    perEngineAvailability: dict[str, bool]
    items: list[RelatedFinding]                  # capped 100, severity DESC

class ComplianceMappingItem(BaseModel):
    framework: str; controlId: str
    controlName: Optional[str]; status: Optional[str]

class ComplianceBlock(BaseModel):
    available: bool
    controlMappings: list[ComplianceMappingItem]

class RemediationStep(BaseModel):
    order: int; action: str; detail: Optional[str] = None

class RemediationBlock(BaseModel):
    available: bool
    steps: list[RemediationStep]
    references: list[str] = []
    estimatedEffort: Optional[str] = None
    slaPriority: Optional[str] = None    # critical=24h, high=72h, medium=30d, low=90d

class EngineExtensions(BaseModel):
    """Plugin slot — engines may register additional tab payloads."""
    model_config = ConfigDict(extra="allow")

class FindingDetailResponse(BaseModel):
    finding: FindingHeader
    resourceContext: Optional[dict] = None       # always None Phase B; FE calls /asset-context separately
    relatedFindings: RelatedFindingsBlock
    compliance: ComplianceBlock
    remediation: RemediationBlock
    engineExtensions: EngineExtensions = Field(default_factory=EngineExtensions)
```

`_finding_engine_map.py` provides `ENGINE_MAP[slug] = {"conn": <fn>, "table": <name>, "perm": "<engine>:read"}` plus a single `STD_SELECT` parameterized query (`finding_id = %s AND tenant_id = %s` — both columns enforced).

## 4. Failure-mode matrix

| Scenario | HTTP | Body |
|---|---|---|
| Unknown engine slug | 400 | `{"detail": "engine must be one of [...]"}` |
| `secops` (until story closed) | 501 | `{"detail": "engine 'secops' not yet supported"}` |
| Finding not found OR cross-tenant probe | 404 | `{"detail": "finding not found"}` (no enumeration leak) |
| DB connection fails (Tab 1) | 503 | `{"detail": "database unavailable", "engine": <slug>}` |
| Tab 3 1+ engines fail | 200 | `relatedFindings.perEngineAvailability` reflects per-engine; no merge |
| Tab 3 ALL fail | 200 | `relatedFindings.available=false`, `items=[]` |
| Tab 4 mapping query fails | 200 | `compliance.available=false` |
| Tab 5 rule_metadata fails | 200 | `remediation.available=false` |
| Auth missing | 401 | gateway-level rejection |
| Permission denied | 403 | `require_permission` raises |
| Path-param injection | 400 | regex rejects |
| `credential_ref/type` in DB row | — | Pydantic `exclude=True` strips |

Constitution §1+§4: 5xx for infra; 200 with `available:false` for engine partials; never fabricate; never merge.

## 5. Cache strategy

| Cache | Backing | TTL | Why |
|---|---|---|---|
| `rule_control_mapping` | `cachetools.TTLCache` (in-process, per-pod) | 5 min | Static-ish reference data |
| `rule_metadata.remediation_guidance` | same | 5 min | Reload-on-deploy |
| Tab 1 finding row | NONE | — | Status changes must be immediate |
| Tab 3 related findings | NONE | — | Defer to Phase C if perf demands |

## 6. Open questions for `bmad-security-architect` (CP-2)

1. **DB-direct from BFF vs HTTP through engines** — confirm "BFF as read-only gateway with privileged DB access" matches §UI-Backend Contract intent.
2. **Cross-engine permission model for Tab 3** — union of all 11 read perms, or filter to permitted engines + return `restrictedEngines: [...]`? Recommend the latter.
3. **Defense-in-depth on credential exclusion** — add a Pydantic `model_validator` asserting `credential_ref/type` keys are never present in serialized output, even in `finding_data` JSONB?
4. **404 vs 403 on cross-tenant probe** — confirm 404-on-cross-tenant matches OWASP A01:2021 guidance.
5. **Path regex allows `/` for ARN-shaped IDs** — confirm no traversal risk given parameterized SQL binding.
6. **`EngineExtensions` trust boundary** — frontend sanitizes (React escapes), BFF blocks denylist keys (`__proto__`, `constructor`)?

## 7. Open questions for engine specialists

| # | Engine | Question | Owner |
|---|---|---|---|
| 1 | `secops` | Canonical finding table name? Standard columns present? Needs `get_secops_conn()` helper. | `cspm-secops-engineer` |
| 2 | `threat` | `threat_findings` vs `threat_detections` — source of truth? | `cspm-threat-engineer` |
| 3 | `ciem` | `ciem_findings.finding_data` is nullable JSONB — coerce null → `{}` confirmed acceptable? | `cspm-ciem-engineer` |
| 4 | `check`+`compliance` | Single `rule_control_mapping` or per-engine variants (`tech_rule_control_mapping`)? Tab 4 join chain. | `cspm-check-engineer` |
| 5 | all | `*_rule_metadata.remediation_guidance` JSONB shape consistent across engines? | `cspm-standards-guardian` |
