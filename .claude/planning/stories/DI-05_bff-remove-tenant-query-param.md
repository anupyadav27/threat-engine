# DI-05: BFF — Remove tenant_id Query Param from All Views (Batch 1: High-Traffic)

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P1 — depends on DI-04

## Story
As a security engineer, I need all high-traffic BFF view handlers to stop accepting `tenant_id` as a query string parameter and instead derive it from `AuthContext`, so that users cannot query another tenant's data by changing a URL parameter.

## Scope of This Story (Batch 1)

This story covers the 12 highest-traffic views. The remaining views are covered in DI-06.

Views to convert:
1. `dashboard.py` — `/api/v1/views/dashboard`
2. `threats.py` — `/api/v1/views/threats`
3. `compliance.py` — `/api/v1/views/compliance` (3 endpoints in this file)
4. `inventory.py` — `/api/v1/views/inventory` (main endpoint)
5. `iam.py` — `/api/v1/views/iam`
6. `risk.py` — `/api/v1/views/risk`
7. `scans.py` — `/api/v1/views/scans`
8. `misconfig.py` — `/api/v1/views/misconfig`
9. `vulnerability.py` — `/api/v1/views/vulnerability`

## Files to Modify

- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/dashboard.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/threats.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/compliance.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/inventory.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/iam.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/risk.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/scans.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/misconfig.py`
- `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/vulnerability.py`

## Pattern to Follow

For every view function in scope:

### Before:
```python
from fastapi import APIRouter, Query, Request

@router.get("/dashboard")
async def view_dashboard(
    request: Request,
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
):
```

### After:
```python
from fastapi import APIRouter, Query, Request
from ._auth import resolve_tenant_id

@router.get("/dashboard")
async def view_dashboard(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
):
    tenant_id = resolve_tenant_id(request)
```

Key rules:
- Remove `tenant_id: str = Query(...)` from function signature entirely
- Add `tenant_id = resolve_tenant_id(request)` as the FIRST LINE of the function body
- All existing uses of `tenant_id` variable inside the function body remain unchanged
- Add import: `from ._auth import resolve_tenant_id` at top of each file
- For compliance.py which has 3 endpoints: convert all 3

## Backward Compatibility

The `useViewFetch` hook in the frontend (`/Users/apple/Desktop/threat-engine/frontend/src/lib/use-view-fetch.js`) currently sends `tenant_id` in the query string (line 36: `tenant_id: tenantId`). That query parameter will now be silently ignored by the BFF (FastAPI ignores unknown query params by default). This is intentional — the server-side source of truth wins.

Do NOT modify `useViewFetch` in this story. It is modified in DI-07.

## Acceptance Criteria

For each converted view:
- [ ] Function signature has no `tenant_id` parameter
- [ ] `tenant_id = resolve_tenant_id(request)` is first line of function body
- [ ] Existing `tenant_id` variable usage inside function body is unchanged
- [ ] GET request without valid session cookie returns HTTP 401
- [ ] GET request with valid session returns the same data as before (same tenant)
- [ ] GET request with a different `?tenant_id=OTHER` query string returns data for the session tenant, not the query string value

## Security Verification
After deploying:
```bash
# Should return 401 (no cookie)
curl http://gateway/api/v1/views/dashboard

# Should return data for session tenant, NOT "other-tenant"
curl -b "access_token=VALID_TOKEN" http://gateway/api/v1/views/threats?tenant_id=other-tenant
```

## Definition of Done
- All 9 files modified per pattern
- Gateway image rebuilt and deployed
- Manual test confirms tenant_id from query string is ignored
- All existing automated tests pass (BFF contract tests from DI-09)
