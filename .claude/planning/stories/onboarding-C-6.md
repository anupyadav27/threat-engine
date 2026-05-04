---
story_id: onboarding-C-6
title: RBAC on schedule and cloud_account endpoints
status: ready
sprint: onboarding-revamp-C
depends_on: [onboarding-C-3]
blocks: [onboarding-C-7, onboarding-C-9, onboarding-D-3, onboarding-D-5]
sme: Python/FastAPI/RBAC engineer
estimate: 1 day
---

# Story: RBAC on schedule and cloud_account endpoints

## User Story
As a security engineer, I want every schedule and cloud_account endpoint to require a
specific RBAC permission so that unauthenticated callers and low-privilege users (viewers)
cannot create, modify, or trigger scans.

## Context
Gap S-01 from USER-FLOWS-SCHEDULING.md: the onboarding engine exposes schedule CRUD
(`POST /api/v1/schedules/`, `GET /api/v1/schedules/`, `PATCH /schedules/{id}`,
`DELETE /schedules/{id}`, `POST /schedules/{id}/run-now`) with no RBAC permission checks.
Story C-3 adds the auth middleware so `X-Auth-Context` is available. This story adds
`require_permission()` calls on all schedule and cloud_account write endpoints.

Current state: `api/schedules.py` and `api/cloud_accounts.py` use `Depends(get_auth_context)`
(or equivalent) but do not call `require_permission("scans:create")` or
`require_permission("cloud_accounts:write")`.

The RBAC permission matrix (`.claude/documentation/RBAC.md`) defines:
- `scans:read` — org_admin, tenant_admin, analyst, viewer (read-only)
- `scans:create` — org_admin, tenant_admin, analyst (create/run scans)
- `cloud_accounts:read` — all 5 roles
- `cloud_accounts:write` — org_admin, tenant_admin only

## Files to Create/Modify
- `engines/onboarding/api/schedules.py` — add `require_permission` to all handlers
- `engines/onboarding/api/cloud_accounts.py` — add `require_permission` to write handlers

## Implementation Notes

### Schedule endpoint permissions

```python
from shared.auth.fastapi.permissions import require_permission

# GET /api/v1/schedules/
@router.get("/schedules/")
async def list_schedules(
    auth: AuthContext = Depends(require_permission("scans:read")),
    ...
):
    ...

# POST /api/v1/schedules/
@router.post("/schedules/")
async def create_schedule(
    auth: AuthContext = Depends(require_permission("scans:create")),
    ...
):
    ...

# PATCH /api/v1/schedules/{schedule_id}
@router.patch("/schedules/{schedule_id}")
async def update_schedule(
    auth: AuthContext = Depends(require_permission("scans:create")),
    ...
):
    ...

# DELETE /api/v1/schedules/{schedule_id}
@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    auth: AuthContext = Depends(require_permission("scans:create")),
    ...
):
    ...

# POST /api/v1/schedules/{schedule_id}/run-now
@router.post("/schedules/{schedule_id}/run-now")
async def run_now(
    auth: AuthContext = Depends(require_permission("scans:create")),
    ...
):
    ...
```

### Cloud account endpoint permissions

```python
# GET /api/v1/cloud-accounts/ — already has auth context; add explicit permission
async def list_accounts(auth: AuthContext = Depends(require_permission("cloud_accounts:read"))):

# POST /api/v1/cloud-accounts/
async def create_account(auth: AuthContext = Depends(require_permission("cloud_accounts:write"))):

# PATCH /api/v1/cloud-accounts/{account_id}
async def update_account(auth: AuthContext = Depends(require_permission("cloud_accounts:write"))):

# DELETE /api/v1/cloud-accounts/{account_id}
async def delete_account(auth: AuthContext = Depends(require_permission("cloud_accounts:write"))):

# POST /api/v1/cloud-accounts/{account_id}/credentials
async def submit_credentials(auth: AuthContext = Depends(require_permission("cloud_accounts:write"))):
```

### Tenant-scoping on list endpoints

After adding RBAC, also verify that list endpoints filter by `auth.engine_tenant_id`:
```python
# In list_schedules:
schedules = await get_schedules_by_tenant(tenant_id=auth.engine_tenant_id)
# NOT: get_all_schedules()
```

## Acceptance Criteria
- [ ] AC1: `GET /api/v1/schedules/` with no auth → 401 or 403
- [ ] AC2: `POST /api/v1/schedules/` with viewer auth context → 403
- [ ] AC3: `POST /api/v1/schedules/` with analyst auth context → 201 (success)
- [ ] AC4: `POST /api/v1/cloud-accounts/` with viewer auth context → 403
- [ ] AC5: `POST /api/v1/cloud-accounts/` with org_admin auth context → success
- [ ] AC6: `GET /api/v1/schedules/` with tenant_admin only sees own tenant's schedules
- [ ] AC7: `POST /api/v1/schedules/{id}/run-now` with analyst context → 202 (success)

## Definition of Done
- [ ] All schedule handlers have `Depends(require_permission(...))`
- [ ] All cloud_account write handlers have `Depends(require_permission(...))`
- [ ] List endpoints filter by `auth.engine_tenant_id`
- [ ] Tests: viewer gets 403 on all write endpoints
- [ ] Tests: analyst gets 201/202 on schedule create/run-now
- [ ] bmad-security-reviewer: no BLOCKERs
