---
id: onboarding-C6
title: "RBAC on schedule + cloud_account endpoints"
sprint: C
points: 1
depends_on: [onboarding-C3]
blocks: [onboarding-C7, onboarding-C9, onboarding-D5]
security_blocks: []
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

Gap S-01: RBAC is missing on the scheduling endpoints in `engines/onboarding/api/schedules.py`. Any authenticated user can create, modify, or delete schedules for accounts they don't own. The `cloud_accounts.py` endpoints also have inconsistent permission requirements — some endpoints have `require_permission()` but with incorrect permission strings. This story audits all schedule and cloud_account endpoints and applies the correct `require_permission()` calls based on the RBAC matrix in the PRD. `tenant_id` must be extracted from `auth.tenant_id` in every query — never trusted from request body. After C3, the auth middleware is in place — this story applies the correct permissions to the right operations.

## Acceptance Criteria

- [ ] AC1 (S-01): Every endpoint in `engines/onboarding/api/schedules.py` has `Depends(require_permission(...))`.
- [ ] AC2: Schedule READ endpoints (`GET /schedules`, `GET /schedules/{id}`) require `scans:read` permission.
- [ ] AC3: Schedule CREATE/UPDATE/DELETE endpoints require `scans:create` permission.
- [ ] AC4: All schedule DB queries filter by `tenant_id = auth.tenant_id` — no schedule is readable/writable across tenant boundary.
- [ ] AC5: `GET /cloud-accounts` requires `cloud_accounts:read` permission and filters by `tenant_id`.
- [ ] AC6: `POST /cloud-accounts` requires `cloud_accounts:write` permission (this should already be from C3 — verify and fix if missing).
- [ ] AC7: `DELETE /cloud-accounts/{id}` requires `cloud_accounts:write` permission.
- [ ] AC8: Viewer role (`viewer` permission set) calling `POST /schedules` returns HTTP 403.
- [ ] AC9: Analyst role calling `GET /schedules` returns HTTP 200 (has `scans:read`).
- [ ] AC10: Cross-tenant test: user from tenant A cannot read/modify schedules belonging to tenant B — returns 403 or 404.
- [ ] AC11: A permission audit comment `# RBAC: requires scans:create` is added above each endpoint decorator for readability.

## Key Files

- `engines/onboarding/api/schedules.py` — Add `Depends(require_permission(...))` to all endpoints
- `engines/onboarding/api/cloud_accounts.py` — Verify all endpoints have correct permissions (audit and fix)
- `engines/onboarding/database/schedule_operations.py` — Ensure all SQL queries filter by `tenant_id`

## Technical Notes

**Audit all schedule endpoints:**
```bash
grep -n "^@router\|async def\|require_permission" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/api/schedules.py
```
For any `async def` that doesn't have `require_permission` in its args, add it.

**Audit all cloud_account endpoints:**
```bash
grep -n "^@router\|async def\|require_permission" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py
```

**Permission string to endpoint mapping:**
```python
# Read-only
GET  /schedules            → require_permission("scans:read")
GET  /schedules/{id}       → require_permission("scans:read")
GET  /cloud-accounts       → require_permission("cloud_accounts:read")
GET  /cloud-accounts/{id}  → require_permission("cloud_accounts:read")

# Write
POST   /schedules          → require_permission("scans:create")
PUT    /schedules/{id}     → require_permission("scans:create")
DELETE /schedules/{id}     → require_permission("scans:create")
POST   /cloud-accounts     → require_permission("cloud_accounts:write")
PATCH  /cloud-accounts/{id}→ require_permission("cloud_accounts:write")
DELETE /cloud-accounts/{id}→ require_permission("cloud_accounts:write")
```

**tenant_id isolation in schedule queries:**
```python
# schedule_operations.py — example query pattern
async def get_schedules(tenant_id: str, conn) -> list:
    return await conn.fetch(
        "SELECT * FROM schedules WHERE tenant_id = $1 ORDER BY created_at DESC",
        tenant_id
    )
# tenant_id comes from auth.tenant_id in the endpoint, passed down here
```

**Standard endpoint pattern:**
```python
@router.get("/schedules")
# RBAC: requires scans:read
async def list_schedules(
    auth: AuthContext = Depends(require_permission("scans:read")),
    db=Depends(get_db),
):
    schedules = await get_schedules(tenant_id=auth.tenant_id, conn=db)
    return schedules
```

**Verify no tenant_id from body:**
```bash
grep -n "tenant_id.*body\|request\.json.*tenant\|body\.tenant_id" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/api/schedules.py \
  /Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py
# Expected: zero hits
```

## Security Checklist

- [ ] Every endpoint in schedules.py has `Depends(require_permission(...))`
- [ ] Every endpoint in cloud_accounts.py has `Depends(require_permission(...))`
- [ ] `tenant_id` from `auth.tenant_id` in ALL queries — not from request body or URL params
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -c "require_permission" engines/onboarding/api/schedules.py` — count equals number of endpoint functions
- [ ] RBAC matrix test: 5 roles × 3 endpoint types (read/write/delete) = 15 test cases
- [ ] bmad-security-reviewer: no BLOCKERs (S-01 resolved)
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: existing schedule reads still work for existing tenants