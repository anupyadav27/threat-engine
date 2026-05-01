# UI-11a (BE-04): Add `GET /api/v1/scan-runs` to onboarding engine

## Status
Ready for dev

## Context
`shared/api_gateway/bff/scans.py` contains a function `_get_scan_history()` (lines 25–48) that directly queries the PostgreSQL `scan_runs` table via `psycopg2`. This is an architectural violation: BFF handlers must only call engine APIs, not connect to databases themselves. The fix is two-part. This story (Part A) adds a proper API endpoint to the onboarding engine that serves scan run history. Part B (UI-11b) then replaces the psycopg2 block in the BFF with a call to this new endpoint.

## Scope
**In scope:**
- New `GET /api/v1/scan-runs` endpoint in `engines/onboarding/`
- Accepts `tenant_id` and optional `limit` query params
- Returns scan runs from the `scan_runs` table (or `scan_orchestration` table — read the schema to confirm the table name)
- Returns the fields listed in the Technical Notes below

**Out of scope:**
- Changing the BFF (that is UI-11b)
- Creating, updating, or deleting scan runs
- Pagination with cursors (use `LIMIT` only)

## Technical Notes

### Read these files first
```bash
# The onboarding engine structure:
ls /Users/apple/Desktop/threat-engine/engines/onboarding/

# The onboarding engine's main router:
find /Users/apple/Desktop/threat-engine/engines/onboarding/ -name "*.py" | xargs grep -l "router\|APIRouter\|app = FastAPI" | head -5

# The BFF scans.py to see what fields are needed:
cat /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/scans.py

# The database schema to confirm the table name and columns:
grep -rn "scan_runs\|scan_orchestration" \
  /Users/apple/Desktop/threat-engine/shared/database/schemas/ --include="*.sql" | head -20
cat /Users/apple/Desktop/threat-engine/shared/database/schemas/onboarding_schema.sql 2>/dev/null || \
  find /Users/apple/Desktop/threat-engine/shared/database/schemas/ -name "*.sql" | xargs ls
```

### Table name
Based on the architecture, the table may be named `scan_runs` or `scan_orchestration`. Read the schema SQL files to confirm. The onboarding engine likely has DB access to whichever table tracks scan lifecycle. Use the actual table name.

### Response shape
```json
{
  "scan_runs": [
    {
      "scan_run_id": "uuid",
      "tenant_id": "uuid",
      "account_id": "string",
      "provider": "aws|azure|gcp|oci|alicloud|k8s",
      "overall_status": "COMPLETED|RUNNING|FAILED|PENDING",
      "started_at": "2026-04-29T10:00:00Z",
      "completed_at": "2026-04-29T10:15:00Z",
      "engines_requested": [...],
      "engines_completed": [...]
    }
  ],
  "total": N
}
```

`engines_requested` and `engines_completed` are JSONB columns — psycopg2 auto-deserializes them to Python dicts/lists. Do NOT call `json.loads()` on them.

### SQL query
```sql
SELECT
  scan_run_id,
  tenant_id,
  account_id,
  provider,
  overall_status,
  started_at,
  completed_at,
  engines_requested,
  engines_completed
FROM scan_runs   -- or scan_orchestration — use actual table name
WHERE tenant_id = %(tenant_id)s
ORDER BY started_at DESC
LIMIT %(limit)s
```

### FastAPI endpoint pattern
Follow the exact pattern used in other onboarding engine endpoints. Read the existing onboarding router file before writing:
```python
@router.get("/api/v1/scan-runs")
async def list_scan_runs(
    tenant_id: str,
    limit: int = Query(50, ge=1, le=500),
    db = Depends(get_db),   # or however the onboarding engine gets DB connections
):
    # Execute query, return response
    ...
```

Note: Find how the onboarding engine gets its DB connection — look for `get_db`, `get_conn`, or a global connection pool. Use the same pattern.

### DB host / credentials
The onboarding engine already connects to a database for other operations. Use the same connection mechanism — do not add new environment variables.

If the `scan_runs` table is in a different database (e.g. the orchestration/onboarding DB, not the discoveries DB), confirm by reading the existing onboarding engine's DB config:
```bash
grep -rn "DB_HOST\|DATABASE_URL\|connect\|psycopg2" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/ --include="*.py" | head -20
```

### Datetime serialization
`started_at` and `completed_at` are `datetime` objects in Python. When returning from FastAPI, use `.isoformat()` or let FastAPI's JSON encoder handle it if a Pydantic response model is used. Follow the pattern in other endpoints.

## Implementation Steps

1. Read `engines/onboarding/` directory structure
2. Read the existing onboarding router to understand the endpoint pattern, DB connection method, and response format
3. Read the database schema to confirm table name and available columns
4. Read `shared/api_gateway/bff/scans.py` lines 25–48 to understand exactly which fields the BFF needs
5. Add the `GET /api/v1/scan-runs` endpoint to the onboarding router
6. Test locally using kubectl port-forward or docker-compose

## Acceptance Criteria

**Given** `GET /api/v1/scan-runs?tenant_id=<t>&limit=10` is called on the onboarding engine
**When** the engine processes the request
**Then** HTTP 200 is returned with `{ "scan_runs": [...], "total": N }` where each element has the fields listed above

**Given** `tenant_id` is not provided
**When** the engine processes the request
**Then** HTTP 422 is returned (FastAPI validation error for missing required param)

**Given** `limit=0` is passed
**When** the engine validates the request
**Then** HTTP 422 is returned (minimum 1 enforced)

**Given** the tenant has no scan runs
**When** the endpoint is called
**Then** HTTP 200 with `{ "scan_runs": [], "total": 0 }`

## Test / Validation
```bash
# Port-forward to onboarding engine:
kubectl port-forward svc/engine-onboarding 8008:80 -n threat-engine-engines &

# Get a tenant_id:
TOKEN=$(curl -s -X POST http://localhost:8008/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@cspm.local","password":"Admin@12345"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
TENANT=$(curl -s -b "access_token=$TOKEN" http://localhost:8008/api/auth/me/ \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['tenants'][0]['tenant_id'])")

# Call the new endpoint:
curl -s "http://localhost:8008/api/v1/scan-runs?tenant_id=$TENANT&limit=10" | python3 -m json.tool
# Expected: JSON with scan_runs array

# Test missing tenant_id:
curl -s "http://localhost:8008/api/v1/scan-runs" | python3 -m json.tool
# Expected: 422 validation error
```

## Definition of Done
- [ ] `GET /api/v1/scan-runs` endpoint added to onboarding engine
- [ ] Accepts `tenant_id` (required) and `limit` (optional, default 50, max 500)
- [ ] Returns `{ "scan_runs": [...], "total": N }` with all required fields
- [ ] JSONB fields (`engines_requested`, `engines_completed`) serialized correctly (not double-encoded)
- [ ] Missing `tenant_id` → 422
- [ ] No scan runs → 200 with empty array
- [ ] Curl test with real tenant ID returns HTTP 200

## Points
2

## Dependencies
None — this story is independent. UI-11b (BFF migration) depends on this story being done and deployed first.