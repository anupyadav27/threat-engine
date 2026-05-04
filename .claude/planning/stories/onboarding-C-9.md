---
story_id: onboarding-C-9
title: Bulk run-all schedules endpoint
status: ready
sprint: onboarding-revamp-C
depends_on: [onboarding-C-6]
blocks: [onboarding-D-11]
sme: Python/FastAPI engineer
estimate: 1 day
---

# Story: Bulk run-all schedules endpoint

## User Story
As a tenant_admin, I want a single button to trigger all active schedules in my tenant
immediately, so that after a major infrastructure change I can refresh all security
findings without clicking run-now on each account individually.

## Context
Gap S-05 from USER-FLOWS-SCHEDULING.md. The existing `POST /schedules/{id}/run-now`
requires one call per schedule. There is no bulk endpoint.

The bulk run-all must:
1. List all `active` schedules for the authenticated tenant.
2. Submit an Argo pipeline run for each schedule (fire-and-forget).
3. Return a summary: `{submitted: N, skipped: M, errors: [...]}`

Skipped cases:
- Account's `credential_validation_status != 'valid'` → skip + add to summary
- Account has `account_status != 'active'` → skip
- Schedule has `status != 'active'` → skip

Rate guard: if more than 20 schedules in one tenant, submit first 20 and return
`{warning: "Capped at 20 concurrent scans — remaining schedules were skipped"}`.
`MAX_CONCURRENT_SCANS` env var (default 10) also caps total across all tenants.

## Files to Create/Modify
- `engines/onboarding/api/schedules.py` — add `POST /api/v1/schedules/run-all`
- `engines/onboarding/database/postgres_operations.py` — add `get_active_schedules_for_tenant()`

## Implementation Notes

### New endpoint

```python
@router.post("/schedules/run-all")
async def run_all_schedules(
    auth: AuthContext = Depends(require_permission("scans:create")),
    db = Depends(get_db),
):
    schedules = await get_active_schedules_for_tenant(db, tenant_id=auth.engine_tenant_id)

    submitted, skipped, errors = [], [], []
    cap = min(int(os.getenv("MAX_CONCURRENT_SCANS", 10)), 20)

    for sched in schedules[:cap]:
        account = await get_cloud_account(db, sched["account_id"], tenant_id=auth.engine_tenant_id)
        if not account or account.get("credential_validation_status") != "valid":
            skipped.append(sched["id"])
            continue
        try:
            scan_run_id = str(uuid.uuid4())
            await create_scan_run_adhoc(db, scan_run_id, account, triggered_by=str(auth.user_id))
            await argo_client.submit_pipeline("cspm-scan-pipeline", _build_argo_params(sched, account, scan_run_id))
            submitted.append(scan_run_id)
        except Exception as e:
            errors.append({"schedule_id": sched["id"], "error": str(e)})

    result = {"submitted": len(submitted), "skipped": len(skipped), "errors": errors}
    if len(schedules) > cap:
        result["warning"] = f"Capped at {cap} concurrent scans — {len(schedules) - cap} schedules not submitted"
    return JSONResponse(result, status_code=202)
```

### `get_active_schedules_for_tenant()`

```python
async def get_active_schedules_for_tenant(db, tenant_id):
    rows = await db.fetch_all("""
        SELECT s.*, ca.credential_validation_status, ca.credential_type, ca.credential_ref,
               ca.provider, ca.account_type
        FROM schedules s
        JOIN cloud_accounts ca ON ca.id = s.account_id
        WHERE s.tenant_id = %s
          AND s.status = 'active'
          AND ca.account_status = 'active'
    """, (tenant_id,))
    return rows
```

## Acceptance Criteria
- [ ] AC1: `POST /api/v1/schedules/run-all` with 3 active schedules → 202, `submitted: 3`
- [ ] AC2: Schedule whose account has `credential_validation_status != 'valid'` → counted in `skipped`
- [ ] AC3: More than 20 schedules → `warning` field in response, first 20 submitted
- [ ] AC4: viewer auth context → 403
- [ ] AC5: Argo submit failure for one schedule → captured in `errors`, others still submitted
- [ ] AC6: Returns 202 even if 0 schedules (empty tenant)

## Definition of Done
- [ ] `POST /schedules/run-all` endpoint added with RBAC
- [ ] `get_active_schedules_for_tenant()` filters by status=active AND credential=valid
- [ ] Cap at MAX_CONCURRENT_SCANS (default 10), hard max 20
- [ ] Tests: 0 schedules, 2 schedules, 25 schedules (cap test), credential invalid skip
- [ ] bmad-security-reviewer: no BLOCKERs
