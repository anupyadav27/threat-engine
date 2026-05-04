---
story_id: onboarding-D-6
title: Scan run history + re-run API via Gateway BFF
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-C-7]
blocks: [onboarding-D-11]
sme: Python/FastAPI/BFF engineer
estimate: 1 day
---

# Story: Scan run history + re-run API via Gateway BFF

## User Story
As a tenant_admin, I want to see a list of past scan runs for my cloud accounts and
re-trigger a previous scan configuration with one click, so that I can audit what was
scanned and quickly re-run after fixing issues.

## Context
The `scan_orchestration` table stores all scan runs. After C7 (ad-hoc scan endpoint),
every run (scheduled + ad-hoc) has a `scan_run_id`, `trigger_type`, `triggered_by`,
`status`, `created_at`, `completed_at`.

This story adds BFF endpoints to:
1. List scan runs for a tenant (paginated, filterable by account_id, status, date range)
2. Get scan run detail (status, engines_completed, finding counts)
3. Re-run: create a new scan run with the same parameters as a previous one

## Files to Create/Modify
- `shared/api_gateway/routes/scan_history.py` — new router
- `shared/api_gateway/main.py` — include scan_history router

## Implementation Notes

### BFF scan history endpoints

```python
# GET /gateway/api/v1/scan-runs/
# Query params: account_id, status, start_date, end_date, page, page_size
@router.get("/api/v1/scan-runs/")
async def list_scan_runs(request: Request, db=Depends(get_onboarding_db)):
    auth = request.state.auth_context
    tenant_id = auth.engine_tenant_id
    # Query scan_orchestration filtered by tenant_id
    ...

# GET /gateway/api/v1/scan-runs/{scan_run_id}/
@router.get("/api/v1/scan-runs/{scan_run_id}")
async def get_scan_run(scan_run_id: str, request: Request, db=Depends(get_onboarding_db)):
    auth = request.state.auth_context
    row = await db.fetchrow("""
        SELECT * FROM scan_orchestration
        WHERE scan_run_id = $1 AND tenant_id = $2
    """, scan_run_id, auth.engine_tenant_id)
    if not row:
        raise HTTPException(404)
    return dict(row)

# POST /gateway/api/v1/scan-runs/{scan_run_id}/re-run
@router.post("/api/v1/scan-runs/{scan_run_id}/re-run")
async def rerun_scan(scan_run_id: str, request: Request):
    auth = request.state.auth_context
    # Fetch original scan parameters, then proxy to onboarding engine /cloud-accounts/{id}/scan
    headers = {"X-Auth-Context": auth.to_header()}
    async with httpx.AsyncClient() as client:
        original = await client.get(f"{ONBOARDING_URL}/api/v1/scan-runs/{scan_run_id}",
                                    headers=headers)
        original_data = original.json()
        resp = await client.post(
            f"{ONBOARDING_URL}/api/v1/cloud-accounts/{original_data['account_id']}/scan",
            headers=headers,
            json={
                "include_regions": original_data.get("include_regions"),
                "include_services": original_data.get("include_services"),
                "engines_requested": original_data.get("engines_requested"),
            },
        )
    return Response(content=resp.content, status_code=resp.status_code,
                    media_type="application/json")
```

### scan_orchestration columns used

- `scan_run_id`, `tenant_id`, `account_id`, `provider`, `status`
- `schedule_id` (NULL for ad-hoc), `triggered_by`, `trigger_type`
- `created_at`, `completed_at`, `engines_requested`, `engines_completed`
- `include_regions`, `include_services` (if stored on the scan run row)

## Acceptance Criteria
- [ ] AC1: `GET /gateway/api/v1/scan-runs/` returns paginated list scoped to `auth.engine_tenant_id`
- [ ] AC2: `GET /gateway/api/v1/scan-runs/?account_id=X` filters to that account only
- [ ] AC3: `GET /gateway/api/v1/scan-runs/{id}` with scan_run_id from different tenant → 404
- [ ] AC4: `POST /gateway/api/v1/scan-runs/{id}/re-run` → 202 with new scan_run_id
- [ ] AC5: viewer auth → 403 on re-run (scans:create required), 200 on list (scans:read)

## Definition of Done
- [ ] list_scan_runs endpoint with pagination and account_id filter
- [ ] get_scan_run with tenant isolation
- [ ] rerun_scan proxies correct params to onboarding engine
- [ ] Tests: list scoping, cross-tenant 404, re-run 202, viewer 403 on re-run
- [ ] bmad-security-reviewer: no BLOCKERs
