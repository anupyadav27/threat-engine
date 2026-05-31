# Canonical BFF + UI Data Flow — Posture Security Pages

**Status:** Design (pre-implementation)  
**Applies to:** All 13 security engine pages (IAM, Network, CDR, DataSec, Encryption, Container, AI, DBSec, Misconfig, Risk, Compliance, Vulnerability, Attack Path)  
**Date:** 2026-05-30

---

## 1. Canonical 3-Step Page Structure

Every posture security page renders three progressive steps:

```
Step 1 — POSTURE OVERVIEW   (always visible, fast, BFF-aggregated)
Step 2 — FINDINGS TABLE     (main tab, filterable, groupable)
Step 3 — RESOURCE PANEL     (slide-in on row click, cross-engine, DI-backed)
```

---

## 2. BFF Endpoint Catalog

### 2a. Per-Engine Overview Endpoints (Step 1 + Step 2 data)

All exist. One per engine. Called via `useViewFetch('{engine}')` → `fetchView('{engine}')`.

| UI Page | BFF Route | BFF Module | Engine Called | DB (fallback) |
|---------|-----------|-----------|--------------|---------------|
| /iam | `GET /api/v1/views/iam` | `bff/iam.py` | engine-iam `/api/v1/iam-security/ui-data` | check_findings (IAM domain) |
| /network-security | `GET /api/v1/views/network-security` | `bff/network_security.py` | engine-network `/api/v1/network/ui-data` | check_findings (network domain) |
| /cdr | `GET /api/v1/views/cdr` | `bff/cdr.py` | engine-cdr `/api/v1/cdr/ui-data` | — |
| /datasec | `GET /api/v1/views/datasec` | `bff/datasec.py` | engine-datasec `/api/v1/datasec/ui-data` | — |
| /encryption | `GET /api/v1/views/encryption` | `bff/encryption.py` | engine-encryption `/api/v1/encryption/ui-data` | — |
| /container-security | `GET /api/v1/views/container-security` | `bff/container_security.py` | engine-container-sec | — |
| /ai-security | `GET /api/v1/views/ai-security` | `bff/ai_security.py` | engine-ai-security | — |
| /database-security | `GET /api/v1/views/database-security` | `bff/database_security.py` | engine-dbsec | — |
| /misconfig | `GET /api/v1/views/misconfig` | `bff/misconfig.py` | engine-check | — |
| /risk | `GET /api/v1/views/risk` | `bff/risk.py` | engine-risk | — |
| /compliance | `GET /api/v1/views/compliance` | `bff/compliance.py` | engine-compliance | — |
| /vulnerability | `GET /api/v1/views/vulnerability` | `bff/vulnerability.py` | engine-vulnerability | — |
| /attack-paths | `GET /api/v1/views/attack-paths` | `bff/attack_paths.py` | engine-attack-path | — |
| /cnapp | `GET /api/v1/views/cnapp` | `bff/cnapp.py` | engine-cnapp (aggregates 7 pillars) | — |
| /cwpp | `GET /api/v1/views/cwpp` | `bff/cwpp.py` | engine-cwpp | — |

**Response shape (all engine views, consistent):**
```json
{
  "pageContext":  { "title", "brief", "tabs" },
  "kpiGroups":   [{ "title", "items": [{ "label", "value", "suffix" }] }],
  "postureScore": 0-100,          // computed in every BFF from severity weights
  "findings":    [...],           // Step 2 table rows
  "filters":     [...],           // dropdown options for FilterBar
  "insightRow":  { ... }          // optional charts data
}
```

**Posture score formula (uniform across all engines):**
```python
weight    = critical*4 + high*2 + medium*1 + low*0.5
max_weight = total_findings * 4
posture_score = max(0, 100 - round((weight / max_weight) * 100)) if max_weight else 100
```

---

### 2b. Global Scope / Filter Bar Endpoint

| UI Component | BFF Route | Module | Engine | Purpose |
|-------------|-----------|--------|--------|---------|
| GlobalFilterBar | `GET /api/v1/views/scope` | `bff/scope.py` | engine-onboarding `/api/v1/cloud-accounts` | Populate Provider/Account/Region dropdowns |

---

### 2c. Step 3 Resource Detail Panel — Existing Endpoints

| Data Needed | BFF Route | Module | DB / Table |
|------------|-----------|--------|-----------|
| Asset base info | `GET /api/v1/views/inventory/asset/{uid}/posture` | `bff/asset_posture.py` | `resource_security_posture` (DI) |
| Cross-engine findings | `GET /api/v1/views/inventory/asset/{uid}/findings` | `bff/asset_findings.py` | `security_findings` (DI) |
| Tenant-wide findings list | `GET /api/v1/views/findings` | `bff/asset_findings.py` | `security_findings` (DI) |

---

### 2d. Step 3 — ONE MISSING ENDPOINT: Resource Context Panel

**Gap:** No single endpoint returns asset identity + inventory fields + relationships for a resource. The panel needs: name, tags, config, and what it connects to.

**New endpoint to build:**

```
GET /api/v1/views/resource/{resource_uid}
```

**Query params:** `provider`, `account`, `region` (optional scope)  
**Permission:** `discoveries:read`  
**DB:** `threat_engine_di` (direct psycopg2 — same pattern as `asset_posture.py`)

**Response shape:**
```json
{
  "resource": {
    "resource_uid":   "arn:aws:s3:::my-bucket",
    "resource_type":  "aws::s3::Bucket",
    "resource_name":  "my-bucket",
    "service":        "s3",
    "provider":       "aws",
    "account_id":     "123456789012",
    "region":         "us-east-1",
    "tags":           {},               // from emitted_fields.Tags (JSONB)
    "config":         {},               // from emitted_fields (JSONB subset)
    "first_seen_at":  "2026-01-01T00:00:00Z",
    "last_seen_at":   "2026-05-30T00:00:00Z"
  },
  "posture": {
    "overall_posture_score":        74,
    "posture_band":                 "medium",
    "critical_count":               2,
    "high_count":                   5,
    "is_internet_exposed":          true,
    "is_encrypted_at_rest":         false,
    "iam_score":                    60,
    "network_score":                40,
    "encryption_score":             30
  },
  "findings_summary": {
    "total":      12,
    "by_engine":  { "iam": 3, "network": 2, "datasec": 5, "encryption": 2 },
    "by_severity":{ "critical": 2, "high": 5, "medium": 4, "low": 1 }
  },
  "relationships": [
    {
      "direction":     "outbound",       // "inbound" | "outbound"
      "relation_type": "ATTACHED_TO",
      "target_uid":    "arn:aws:iam::123:role/my-role",
      "target_type":   "aws::iam::Role",
      "target_name":   "my-role"
    }
  ]
}
```

**SQL queries (3, all tenant-scoped, run in parallel):**

```sql
-- Q1: asset inventory (latest scan for this resource)
SELECT resource_uid, resource_type, resource_name, service, provider,
       account_id, region,
       emitted_fields->'Tags' AS tags,
       emitted_fields AS config,
       first_seen_at, last_seen_at
FROM asset_inventory
WHERE tenant_id = %s AND resource_uid = %s
ORDER BY last_seen_at DESC LIMIT 1;

-- Q2: posture dimensions
SELECT overall_posture_score, posture_band, critical_count, high_count,
       medium_count, low_count, is_internet_exposed_with_critical,
       is_encrypted_at_rest, iam_score, network_score, encryption_score,
       api_security_score, container_security_score, ai_security_score, dbsec_score
FROM resource_security_posture
WHERE tenant_id = %s AND resource_uid = %s
ORDER BY last_updated_at DESC LIMIT 1;

-- Q3: relationships (inbound + outbound, limit 50)
SELECT
  CASE WHEN source_uid = %s THEN 'outbound' ELSE 'inbound' END AS direction,
  relation_type,
  CASE WHEN source_uid = %s THEN target_uid ELSE source_uid END AS peer_uid,
  CASE WHEN source_uid = %s THEN target_type ELSE source_type END AS peer_type,
  relation_metadata
FROM asset_relationships
WHERE tenant_id = %s AND (source_uid = %s OR target_uid = %s)
ORDER BY last_seen_at DESC LIMIT 50;
```

**Findings summary:** read from existing `asset_findings.py` `get_asset_findings()` helper (already built).

---

### 2e. Deferred (future sprint — schema change required)

| Feature | What's Needed | Effort |
|---------|--------------|--------|
| Trend sparkline on posture score | `posture_score_history` table — written at end of each scan_run | New migration + writer in each engine |
| Saved views (user column prefs server-side) | `user_column_preferences` table in platform DB | Medium |
| Cross-engine resource timeline | Sorted merge of `security_findings.first_seen_at` per resource | Can be done with `asset_findings.py` today if sorted by date |

---

## 3. Full Auth Chain

```
┌─ Browser ───────────────────────────────────────────────────────────────────┐
│  access_token cookie (HttpOnly, Secure, SameSite=Lax)                       │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ HTTPS request + cookie
┌─ API Gateway (middleware.js) ────▼──────────────────────────────────────────┐
│  1. Reads access_token cookie                                               │
│  2. POST /api/auth/verify → Django platform                                 │
│  3. Django returns AuthContext: { engine_tenant_id, tenant_ids,             │
│       account_ids, role, permissions[], is_platform_level }                 │
│  4. Gateway serialises AuthContext → JSON → base64                          │
│  5. Adds X-Auth-Context: <base64> header on every upstream request          │
│  6. Global filter params (provider, account, region) passed as query params │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ Internal HTTP (K8s ClusterIP)
┌─ BFF View Handler ───────────────▼──────────────────────────────────────────┐
│  resolve_tenant_id(request)                                                 │
│    → parses X-Auth-Context                                                  │
│    → checks x-active-tenant-id header (platform_admin override)            │
│    → returns engine_tenant_id (never from query string)                     │
│                                                                             │
│  auth_ctx_header = request.headers.get("X-Auth-Context")                   │
│  fwd_headers = {"X-Auth-Context": auth_ctx_header}                         │
│                                                                             │
│  fetch_many([("engine", "/path", {"tenant_id": tenant_id, ...})],          │
│             auth_headers=fwd_headers)                                       │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ Internal HTTP (K8s ClusterIP)
┌─ Engine (FastAPI) ───────────────▼──────────────────────────────────────────┐
│  Depends(require_permission("discoveries:read"))                            │
│    → parses X-Auth-Context                                                  │
│    → checks permissions[]                                                   │
│    → raises HTTP 403 if missing                                             │
│                                                                             │
│  DB query: WHERE tenant_id = %s  ← from engine_tenant_id, never from URL   │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ psycopg2 / RDS
┌─ PostgreSQL (RDS) ───────────────▼──────────────────────────────────────────┐
│  Row-level tenant isolation — tenant_id in every WHERE clause               │
│  No RLS policies (application-enforced; verified at BFF + engine layers)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Per-role RBAC on Step 3 fields** (`strip_sensitive_fields()` in BFF):

| Role | `iam_detail` | `credential_ref` | CDR `detail` | Posture score |
|------|-------------|-----------------|-------------|--------------|
| platform_admin / org_admin | ✅ full | ✅ | ✅ full | ✅ |
| tenant_admin / analyst | ❌ stripped | ❌ stripped | ✅ actor_hash removed | ✅ |
| viewer | ❌ stripped | ❌ stripped | ❌ stripped | ✅ read-only |

---

## 4. UI → BFF → Engine/DB Data Flow Map

### Step 1: Posture Overview (KPI strip)

```
UI: useViewFetch('{engine}')
  → fetchView('{engine}', { provider, account, region })
  → GET /gateway/api/v1/views/{engine}?provider=&account=&region=
  → BFF: fetch_many([("engine", "/api/v1/{engine}/ui-data", { tenant_id, csp, scan_id })])
  → Engine DB: SELECT severity, COUNT(*) FROM {engine}_findings WHERE tenant_id=%s GROUP BY severity
  → BFF computes: posture_score = max(0, 100 - round(weight/max_weight * 100))
  → Returns: { kpiGroups, postureScore, findings, filters }
  → UI: renders KPI cards, posture score gauge, severity donut
```

**Data guaranteed available:** severity counts from engine findings table for every engine.  
**What engine BFF views return for Step 1:** Already consistent — `postureScore`, `kpiGroups` with Critical/High/Medium/Low counts, total resources affected.

### Step 2: Findings Table

```
UI: DataTable renders tabData[activeTab].data (from same BFF response)
  → FilterBar: client-side filter on findings[] array
  → GroupBy: DataTable groups by accessorKey column value
  → Column picker: localStorage[cspm_cols_{page}_{tab}]
  → Row click → triggers Step 3
```

**Data guaranteed available:** findings[] in every engine BFF response.  
**No additional BFF call needed for Step 2** — data is in the Step 1 response.

### Step 3: Resource Detail Panel (slide-in)

```
UI: row click → setSelectedFinding(row) → FindingDetailPanel opens
  → panel calls two endpoints in parallel:
    1. GET /gateway/api/v1/views/resource/{resource_uid}    ← NEW endpoint
    2. GET /gateway/api/v1/views/inventory/asset/{uid}/findings  ← EXISTS
  → NEW endpoint queries DI DB:
    - asset_inventory (resource identity + config)
    - resource_security_posture (cross-engine posture dims)
    - asset_relationships (graph edges, limit 50)
  → Existing endpoint queries DI DB:
    - security_findings (all findings across all engines for this resource)
  → Panel renders:
    - Resource card (name, ARN/UID, type, region, account, tags)
    - Posture dimension badges (IAM/Network/Encryption/DataSec scores)
    - Findings by engine (tabbed mini-table)
    - Relationships list (inbound/outbound, clickable)
```

**Data available now:**
- `security_findings`: ✅ cross-engine, tenant-scoped, `idx_sf_resource` index
- `resource_security_posture`: ✅ all dimensions, written by each engine
- `asset_inventory`: ✅ resource identity, `emitted_fields` JSONB for tags/config
- `asset_relationships`: ✅ edges with relation_type and metadata

**Missing only:** The single aggregating BFF endpoint (`/views/resource/{uid}`) — one file to write.

---

## 5. End-to-End Quality Check Plan

### Level 0: Schema / Data Check (DB direct)

Run after each scan. Verify data exists before testing BFF.

```sql
-- For each engine, confirm findings exist for this scan_run_id
SELECT source_engine, COUNT(*), MAX(last_seen_at)
FROM security_findings
WHERE tenant_id = '{tenant_id}'
GROUP BY source_engine;

-- Confirm posture rows written
SELECT provider, COUNT(*), AVG(overall_posture_score)
FROM resource_security_posture
WHERE tenant_id = '{tenant_id}'
GROUP BY provider;

-- Confirm relationships written
SELECT relation_type, COUNT(*)
FROM asset_relationships
WHERE tenant_id = '{tenant_id}'
GROUP BY relation_type;

-- Confirm asset inventory populated
SELECT service, COUNT(*)
FROM asset_inventory
WHERE tenant_id = '{tenant_id}'
GROUP BY service ORDER BY 2 DESC LIMIT 10;
```

**Pass criteria:** All source engines represented in `security_findings`; `resource_security_posture` count > 0; `asset_relationships` count > 0.

---

### Level 1: Engine Endpoint Check

Direct engine call via port-forward. Confirms engine is healthy and returns data.

```bash
# Example for IAM
kubectl port-forward svc/engine-iam 8003:80 -n threat-engine-engines &
curl -s "http://localhost:8003/api/v1/iam-security/ui-data?tenant_id={tenant_id}&csp=aws" \
  -H "X-Auth-Context: {base64_auth_ctx}" | jq '{total: .summary.total_findings, score: .summary.posture_score}'
```

**Pass criteria:** HTTP 200, `total_findings > 0`, `posture_score` is a number 0–100.  
**Failure path:** Engine DB unreachable → 503; no data for tenant → empty response (check L0 first).

---

### Level 2: BFF View Check

```bash
# Via ELB (production path)
curl -s "https://{elb}/gateway/api/v1/views/iam?provider=aws" \
  -H "Cookie: access_token={token}" | jq '{score: .postureScore, findings: (.findings | length), kpis: (.kpiGroups | length)}'

# Check every engine view in one loop
for page in iam network-security cdr datasec encryption container-security ai-security database-security misconfig risk; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://{elb}/gateway/api/v1/views/$page" -H "Cookie: access_token={token}")
  echo "$page → $code"
done
```

**Pass criteria:** All views return HTTP 200; `postureScore` field present; `findings` array non-empty; `kpiGroups` has ≥2 groups.  
**Failure modes:** 
- 401 → token expired or gateway auth down
- 503 → engine unreachable (check L1)
- 200 but empty findings → check L0 (no scan data)
- Missing `postureScore` field → BFF module not updated

---

### Level 3: Auth Isolation Check

Confirms tenant scoping. Run with two different tenant tokens.

```bash
# Tenant A should see ONLY its own data
COUNT_A=$(curl -s "https://{elb}/gateway/api/v1/views/findings" \
  -H "Cookie: access_token={token_tenant_a}" | jq '.total')

COUNT_B=$(curl -s "https://{elb}/gateway/api/v1/views/findings" \
  -H "Cookie: access_token={token_tenant_b}" | jq '.total')

# Cross-tenant isolation: tenant A's resource_uid must NOT appear in tenant B's findings
RESOURCE_UID=$(curl -s "https://{elb}/gateway/api/v1/views/findings" \
  -H "Cookie: access_token={token_tenant_a}" | jq -r '.findings[0].resource_uid')

curl -s "https://{elb}/gateway/api/v1/views/resource/$RESOURCE_UID" \
  -H "Cookie: access_token={token_tenant_b}" | jq '.resource'
# Must return null or 404 — never tenant A's data
```

**Pass criteria:** Tenant A resource not accessible by Tenant B. viewer role gets 403 on datasec/secops/vuln/ai/encryption/dbsec/container endpoints.

---

### Level 4: BFF → UI Rendering Check

Manual / Playwright check for each page. Verifies Step 1/2/3 render correctly.

| Check | Step | Pass criteria |
|-------|------|--------------|
| KPI cards visible | 1 | 4+ KPI cards rendered, no "0" values when data exists |
| Posture score | 1 | Number between 0–100 shown |
| Findings table | 2 | Rows visible, sortable, severity badge colored correctly |
| Group By | 2 | Group By menu opens, grouping rows by severity works |
| Column picker | 2 | Columns can be hidden; preference survives page reload (localStorage) |
| Side panel opens | 3 | Click row → panel slides in within 500ms |
| Panel has asset info | 3 | resource_uid, type, region shown |
| Panel has posture dims | 3 | IAM/Network/Encryption scores visible |
| Panel has relationships | 3 | ≥1 relationship shown (if data exists) |
| GlobalFilter scopes data | all | Changing account → findings count changes |

---

### Level 5: Step 3 Cross-Engine Panel Data Correctness

Verifies the new `/views/resource/{uid}` endpoint returns correct merged data.

```bash
# Get a resource_uid from a known finding
RESOURCE_UID=$(curl -s "https://{elb}/gateway/api/v1/views/findings?limit=1" \
  -H "Cookie: access_token={token}" | jq -r '.findings[0].resource_uid')

# Fetch the panel data
curl -s "https://{elb}/gateway/api/v1/views/resource/$RESOURCE_UID" \
  -H "Cookie: access_token={token}" | jq '{
    has_resource: (.resource != null),
    has_posture:  (.posture != null),
    relationship_count: (.relationships | length),
    finding_engines: (.findings_summary.by_engine | keys)
  }'
```

**Pass criteria:**
- `has_resource: true` — asset_inventory has the resource
- `has_posture: true` — resource_security_posture has a row
- `relationship_count > 0` — asset_relationships populated
- `finding_engines` lists ≥1 engine — security_findings has rows

**Data gaps to flag:**
- `has_posture: false` → engine posture writers not running for this resource type
- `relationship_count == 0` → catalog relationship rules don't cover this service
- `finding_engines` missing expected engine → that engine's security_findings writer is broken

---

## 6. CDR-02 Sprint Review

### Story status vs canonical layout

| Story | Priority | BFF change needed | UI change needed | Status |
|-------|----------|------------------|-----------------|--------|
| **CDR-2-S01**: L2 correlation timeline in panel | P0 | None — direct engine call via `getFromEngine('cdr', '/findings/{id}/timeline')` | Add `CorrelationTimeline` component to `FindingDetailPanel` when `rule_source='log_correlation'` | Not started |
| **CDR-2-S02**: 14-day baseline trend sparkline | P1 | Add `baseline_trend` section to `GET /views/cdr/identity` in `bff/cdr_identity.py`; engine needs `GET /api/v1/cdr/actor/{principal}/baseline-trend` | Wire sparkline into identity row expansion | Not started |
| **CDR-2-S03**: Identity heatmap wire | P1 | BFF exists: `GET /api/v1/views/cdr/heatmap` already in `bff/cdr.py` | Confirm component renders; BFF data already fetched (`cdr/heatmap`) | Not started |
| **CDR-2-S04**: Sequence detections section | P1 | Add `sequence_detections` array to `/views/cdr` BFF response (filter `security_findings WHERE source_engine='cdr' AND detail->>'rule_source'='sequence'`) | Add "Sequences" tab to CDR page tabData | Not started |

### CDR-02 BFF changes detail

**CDR-2-S01 (no BFF needed):**
```js
// In FindingDetailPanel, when finding.rule_source === 'log_correlation':
const timeline = await getFromEngine('cdr', `/api/v1/cdr/findings/${finding.finding_id}/timeline`);
```
Auth header forwarded automatically by `getFromEngine()`. No BFF change.

**CDR-2-S02 — add to `bff/cdr_identity.py`:**
```python
# Fetch from engine: GET /api/v1/cdr/actor/{encoded_principal}/baseline-trend
# Engine queries: cdr_actor_daily_stats + cdr_baselines WHERE tenant_id=%s AND actor_principal=%s
# Returns: { metrics: [{ name, dates[], values[], mean, stddev }] }
# Add to view response as: "baseline_trend": { ... }
```
The engine endpoint does not exist yet — needs to be added to `engines/cdr/cdr_engine/api_server.py`.

**CDR-2-S04 — add to `bff/cdr.py`:**
```python
# Add to fetch_many() parallel calls:
("cdr", "/api/v1/cdr/findings", {
    "tenant_id": tenant_id,
    "rule_source": "sequence",
    "limit": 10,
    "scan_run_id": scan_id,
}),

# Add to response:
"sequence_detections": [
    {
        "finding_id": ...,
        "title": ...,
        "severity": ...,
        "step_count": ...,      # from detail.total_steps
        "actor_principal": ..., # from detail.actor_principal
        "techniques": [...],    # from detail.all_mitre_techniques
        "first_event_at": ...,
        "last_event_at": ...,
    }
]
```

### CDR page canonical tab structure (target)

```
/cdr page tabs:
  Overview     → KPI strip + heatmap (CDR-2-S03)
  Detections   → findings DataTable (already exists)
  Sequences    → sequence_detections DataTable (CDR-2-S04) ← NEW
  Events       → log sources (already exists)
  Identities   → identity risk table + baseline trends (CDR-2-S02)
```

---

## 7. Implementation Order (by dependency)

```
Sprint A (no new schema needed):
  1. Write GET /api/v1/views/resource/{uid} BFF endpoint  (Step 3 panel)
  2. Wire FindingDetailPanel to call it on row click (all engine pages)
  3. CDR-2-S03: confirm heatmap renders (BFF already exists)
  4. CDR-2-S04: add sequence_detections to /views/cdr response + Sequences tab

Sprint B (engine change needed):
  5. CDR-2-S01: add CorrelationTimeline component + direct engine call
  6. CDR-2-S02: add engine endpoint + BFF baseline_trend section + sparkline UI

Sprint C (schema migration needed):
  7. posture_score_history table migration + writer in each engine scan run
  8. Trend sparkline on Step 1 KPI strip (all pages)
```

---

## 8. Files to Create / Modify

### New files
| File | Purpose |
|------|---------|
| `shared/api_gateway/bff/resource_detail.py` | `GET /views/resource/{uid}` — Step 3 panel |
| `frontend/src/components/shared/ResourceDetailPanel.jsx` | Step 3 slide-in panel component |
| `frontend/src/app/cdr/_components/CorrelationTimeline.jsx` | CDR-2-S01 timeline component |

### Modified files
| File | Change |
|------|--------|
| `shared/api_gateway/bff/__init__.py` | Import + register `resource_detail` router |
| `shared/api_gateway/bff/cdr.py` | Add `sequence_detections` to response (CDR-2-S04) |
| `shared/api_gateway/bff/cdr_identity.py` | Add `baseline_trend` section (CDR-2-S02) |
| `engines/cdr/cdr_engine/api_server.py` | Add `/actor/{principal}/baseline-trend` endpoint (CDR-2-S02) |
| `frontend/src/app/cdr/page.jsx` | Add Sequences tab; wire CorrelationTimeline; confirm heatmap |
| All engine `page.jsx` files (13) | Replace `FindingDetailPanel` call with `ResourceDetailPanel` call |