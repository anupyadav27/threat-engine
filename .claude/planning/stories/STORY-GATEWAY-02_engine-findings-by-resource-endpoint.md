# STORY-GATEWAY-02: Engine Findings-by-Resource Endpoint (6 Priority Engines)

## Track
Investigation Flow — Critical Path Sprint

## Priority
P0 — STORY-GATEWAY-01 degrades gracefully without these, but asset-context shows no data until they exist

## Story
As the gateway asset-context aggregator (STORY-GATEWAY-01), I need each engine to expose `GET /findings?resource_uid=...` so the investigation panel can show per-engine counts and top findings for any clicked resource.

## Current State

None of the 6 priority engines expose a `GET /findings?resource_uid=` query endpoint. Each has a BFF data endpoint (`/api/v1/{engine}/ui-data`) returning all scan findings — not filterable by `resource_uid`. The gateway cannot fetch per-resource summaries from any of these engines today.

Engines to implement (in priority order):

| # | Engine | DB Table | Gateway Prefix | API Server File |
|---|--------|----------|----------------|-----------------|
| 1 | IAM | `iam_findings` | `/api/v1/iam-security` | `engines/iam/iam_engine/api_server.py` |
| 2 | Network | `network_findings` | `/api/v1/network-security` | `engines/network-security/network_security_engine/api_server.py` |
| 3 | Container | `container_sec_findings` | `/api/v1/container-security` | `engines/container-security/container_security_engine/api_server.py` |
| 4 | DBSec | `dbsec_findings` | `/api/v1/database-security` | `engines/database-security/database_security_engine/api_server.py` |
| 5 | AI Security | `ai_security_findings` | `/api/v1/ai-security` | `engines/ai-security/ai_security_engine/api_server.py` |
| 6 | CIEM | `ciem_findings` | `/api/v1/ciem` | `engines/ciem/ciem_engine/api_server.py` |

## Universal Contract (same for all 6 engines)

### Request

```
GET /api/v1/{engine-prefix}/findings
  ?resource_uid={url-encoded ARN or resource ID}   — required
  &tenant_id={uuid}                                 — required (from X-Auth-Context)
  &scan_run_id=latest|{uuid}                        — optional, default "latest"
  &limit={int}                                      — optional, default 50, max 100
  &status=FAIL|PASS|WARN                            — optional, default all
```

### Response Pydantic model (add to each engine's `api_server.py`)

```python
from pydantic import BaseModel
from typing import Optional

class FindingItem(BaseModel):
    finding_id: str
    title: str
    severity: str           # critical | high | medium | low
    status: str             # FAIL | PASS | WARN
    rule_id: Optional[str] = None
    resource_uid: str
    resource_type: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    provider: Optional[str] = None
    first_seen_at: str      # ISO 8601
    last_seen_at: str

class FindingsByResourceResponse(BaseModel):
    findings: list[FindingItem]
    total: int              # total matching rows (not capped by limit)
    resource_uid: str
    scan_run_id: str        # resolved scan_run_id used for the query
```

### SQL pattern (substitute `{table}` per engine)

```sql
-- Step 1: resolve scan_run_id when "latest"
SELECT scan_run_id
FROM {table}
WHERE tenant_id = %(tenant_id)s
  AND resource_uid = %(resource_uid)s
  {status_clause}
ORDER BY last_seen_at DESC
LIMIT 1;

-- Step 2: count total matching rows
SELECT COUNT(*)
FROM {table}
WHERE tenant_id = %(tenant_id)s
  AND resource_uid = %(resource_uid)s
  AND scan_run_id = %(resolved_scan_run_id)s
  {status_clause};

-- Step 3: fetch top N sorted by severity
SELECT
  finding_id, {title_expr} AS title, severity, status,
  rule_id, resource_uid, resource_type, account_id, region, provider,
  first_seen_at, last_seen_at
FROM {table}
WHERE tenant_id = %(tenant_id)s
  AND resource_uid = %(resource_uid)s
  AND scan_run_id = %(resolved_scan_run_id)s
  {status_clause}
ORDER BY
  CASE severity
    WHEN 'critical' THEN 4 WHEN 'high' THEN 3
    WHEN 'medium'   THEN 2 WHEN 'low'  THEN 1 ELSE 0
  END DESC,
  last_seen_at DESC
LIMIT %(limit)s;
```

If no rows match Step 1 (resource not in this scan), return `{"findings": [], "total": 0, "resource_uid": ..., "scan_run_id": "latest"}` — HTTP 200, not 404.

## Engine-Specific Notes

### 1. IAM — `iam_findings`

```python
# title_expr: COALESCE(finding_data->>'title', finding_data->>'recommendation', rule_id)
# — title is stored in finding_data JSONB, not a native column
# Endpoint path: GET /api/v1/iam-security/findings
# Permission decorator: @require_permission("iam:read")
# DB env var: IAM_DB_HOST / IAM_DB_NAME (pattern from existing api_server.py)
```

### 2. Network — `network_findings`

```python
# title_expr: title   (native VARCHAR(500) column — no JSONB extraction needed)
# Also include in SELECT: network_layer, effective_exposure
# Extend FindingItem with these optional fields in the network engine's version:
#   network_layer: Optional[str]         # L1_topology … L7_flow
#   effective_exposure: Optional[str]    # internet | cross_vpc | vpc_internal | subnet_only | isolated
# Endpoint path: GET /api/v1/network-security/findings
# Permission: @require_permission("network:read")
```

### 3. Container Security — `container_sec_findings`

```python
# title_expr: title   (TEXT column)
# Also include in SELECT: container_service, cluster_name, security_domain
# Extend FindingItem with:
#   container_service: Optional[str]     # eks | ecs | ecr | fargate | lambda | k8s
#   cluster_name: Optional[str]
#   security_domain: Optional[str]       # cluster_security | workload_security | …
# Endpoint path: GET /api/v1/container-security/findings
# Permission: @require_permission("container_security:read")
```

### 4. Database Security — `dbsec_findings`

```python
# title_expr: COALESCE(title, finding_data->>'title', rule_id)
# Also include in SELECT: db_engine, security_domain
# Extend FindingItem with:
#   db_engine: Optional[str]            # mysql | postgres | aurora-mysql | redis | …
#   security_domain: Optional[str]      # access_control | encryption | audit_logging | …
# Endpoint path: GET /api/v1/database-security/findings
# Permission: @require_permission("database_security:read")
```

### 5. AI Security — `ai_security_findings`

```python
# title_expr: title   (native VARCHAR(500) column)
# Also include in SELECT: ml_service, model_type, category
# Extend FindingItem with:
#   ml_service: Optional[str]           # sagemaker | bedrock | rekognition | …
#   model_type: Optional[str]
#   category: Optional[str]             # model_security | endpoint_security | …
# Endpoint path: GET /api/v1/ai-security/findings
# Permission: @require_permission("ai_security:read")
# Note: credential_ref column MUST be excluded from SELECT
```

### 6. CIEM — `ciem_findings`

```python
# title_expr: COALESCE(title, rule_id)
# resource_uid in CIEM is the identity ARN stored as actor_principal
# WHERE clause must use:
#   (resource_uid = %(resource_uid)s OR actor_principal = %(resource_uid)s)
# Also include in SELECT: anomaly_type, anomaly_score, event_count
# Extend FindingItem with:
#   anomaly_type: Optional[str]
#   anomaly_score: Optional[float]
#   event_count: Optional[int]
# Endpoint path: GET /api/v1/ciem/findings   (this path already exists for listing;
#                add resource_uid filter param to existing handler)
# Permission: @require_permission("ciem:read")
```

## FastAPI Handler Template (paste into each engine's api_server.py)

```python
@router.get("/findings", response_model=FindingsByResourceResponse)
async def get_findings_by_resource(
    resource_uid: str = Query(..., description="Full resource ARN or UID"),
    tenant_id: str = Query(...),
    scan_run_id: str = Query("latest"),
    limit: int = Query(50, ge=1, le=100),
    status: Optional[str] = Query(None),
    auth: AuthContext = Depends(require_permission("{engine}:read")),
):
    """Return findings for a specific resource_uid — used by gateway asset-context aggregator."""
    # Always scope by tenant from AuthContext, not query param
    scoped_tenant = auth.tenant_id

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            status_clause = "AND status = %(status)s" if status else ""
            params: dict = {
                "tenant_id": scoped_tenant,
                "resource_uid": resource_uid,
                "status": status,
                "limit": limit,
            }

            # Resolve scan_run_id
            cur.execute(f"""
                SELECT scan_run_id FROM {TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND resource_uid = %(resource_uid)s
                  {status_clause}
                ORDER BY last_seen_at DESC LIMIT 1
            """, params)
            row = cur.fetchone()
            if not row:
                return FindingsByResourceResponse(
                    findings=[], total=0,
                    resource_uid=resource_uid, scan_run_id=scan_run_id
                )
            resolved_scan = row[0]
            params["resolved_scan"] = resolved_scan

            # Total count
            cur.execute(f"""
                SELECT COUNT(*) FROM {TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND resource_uid = %(resource_uid)s
                  AND scan_run_id = %(resolved_scan)s
                  {status_clause}
            """, params)
            total = cur.fetchone()[0]

            # Top N findings
            cur.execute(f"""
                SELECT finding_id, {TITLE_EXPR} AS title, severity, status,
                       rule_id, resource_uid, resource_type, account_id,
                       region, provider, first_seen_at, last_seen_at
                       {EXTRA_COLS}
                FROM {TABLE}
                WHERE tenant_id = %(tenant_id)s
                  AND resource_uid = %(resource_uid)s
                  AND scan_run_id = %(resolved_scan)s
                  {status_clause}
                ORDER BY
                  CASE severity
                    WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2   WHEN 'low'  THEN 1 ELSE 0
                  END DESC,
                  last_seen_at DESC
                LIMIT %(limit)s
            """, params)
            cols = [d[0] for d in cur.description]
            findings = [FindingItem(**dict(zip(cols, r))) for r in cur.fetchall()]

    return FindingsByResourceResponse(
        findings=findings,
        total=total,
        resource_uid=resource_uid,
        scan_run_id=resolved_scan,
    )
```

## Acceptance Criteria

- [ ] `GET /api/v1/iam-security/findings?resource_uid={arn}&tenant_id={tid}` → 200 with correct shape
- [ ] Same for: network-security, container-security, database-security, ai-security, ciem
- [ ] `total` reflects all matching rows, not just the `limit` slice
- [ ] `scan_run_id=latest` resolves to the most recent scan that has findings for `resource_uid`
- [ ] `scan_run_id=latest` with no findings → `{ "findings": [], "total": 0 }` — HTTP 200 (not 404)
- [ ] `status=FAIL` filter excludes PASS/WARN from both `findings` list and `total`
- [ ] `limit` capped at 100 server-side regardless of query param value
- [ ] All SQL uses `%(param)s` placeholders — no f-string interpolation of user input
- [ ] `tenant_id` from `AuthContext` (not query param) used in all WHERE clauses
- [ ] `credential_ref` column NOT in SELECT list on any engine
- [ ] `require_permission()` enforced on each engine endpoint

## Security Checklist

- [ ] `resource_uid` in SQL as `%(resource_uid)s` — never `f"... = '{resource_uid}'""`
- [ ] `tenant_id` always in WHERE — multi-tenant isolation confirmed by code review
- [ ] `limit` validated with `ge=1, le=100` in FastAPI Query — no uncapped queries
- [ ] `credential_ref` excluded from SELECT at query level, not stripped post-fetch
- [ ] No `SELECT *` — explicit column list in every query

## Definition of Done

- [ ] All 6 engines return correct `FindingsByResourceResponse` shape
- [ ] STORY-GATEWAY-01 asset-context response populates real finding data from all 6
- [ ] IAM: query a known role ARN → returns its `iam_findings` rows
- [ ] Network: query a known VPC/SG resource_uid → returns `network_findings` with `network_layer` field
- [ ] `credential_ref` absent from all engine responses (verify with `grep` on response JSON)
- [ ] No `SELECT *` in any of the 6 new handler implementations