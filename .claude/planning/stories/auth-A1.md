---
id: auth-A1
title: "Django migrations — cleanup + customer_id backfill + tenant_type"
sprint: A
points: 2
depends_on: []
blocks: [auth-A2, auth-B4, onboarding-D1, onboarding-D4]
security_blocks: []
nist_csf: GV
owasp_samm: Design
csa_ccm: AIS-04
status: done
---

## Context

The Django platform DB (`threat_engine_platform`) already has `customer_id` columns on `user_auth_users` and `tenant_management_tenants` (migration 0007), but legacy rows created before 0007 may still have `customer_id = NULL`. A `tenant_type` column does not yet exist on `tenant_management_tenants`. This migration (Django 0016) performs three steps: backfill NULL `customer_id` values on both tables, add the `tenant_type` VARCHAR(30) column with default `'cloud'`, and print a verification count. The `NOT NULL` constraint on `customer_id` is NOT applied in this migration — it is deferred to a post-deploy manual step after backfill is confirmed. All downstream stories that enforce org-boundary (auth-B4) or read `tenant_type` (onboarding-D4, onboarding-D7) block on this migration completing.

## Acceptance Criteria

- [ ] AC1: Django migration `0016_cleanup_customer_id.py` exists under `platform/cspm-backend/tenant_management/migrations/` and applies cleanly via `python manage.py migrate tenant_management 0016`.
- [ ] AC2: After migration, `SELECT COUNT(*) FROM user_auth_users WHERE customer_id IS NULL` returns 0.
- [ ] AC3: After migration, `SELECT COUNT(*) FROM tenant_management_tenants WHERE customer_id IS NULL` returns 0.
- [ ] AC4: Column `tenant_management_tenants.tenant_type` exists with type `VARCHAR(30)`, `NOT NULL`, default `'cloud'`.
- [ ] AC5: All existing tenant rows have `tenant_type = 'cloud'` (the backfill default).
- [ ] AC6: Migration does NOT set `customer_id NOT NULL` constraint — that step is deferred (post-deploy manual SQL listed in Technical Notes).
- [ ] AC7: `python manage.py migrate` is idempotent — running it twice does not error.
- [ ] AC8: No reference to `organizations` or `org_id` field appears in any new or modified file.
- [ ] AC9: The migration file includes a `RunSQL` step that prints a completion marker readable in pod logs (`SELECT 'MIGRATION 0016 COMPLETE'`).

## Key Files

- `platform/cspm-backend/tenant_management/migrations/0016_cleanup_customer_id.py` — Create this file
- `platform/cspm-backend/tenant_management/models.py` — Add `tenant_type` field to `Tenant` model
- `platform/cspm-backend/tenant_management/serializers.py` — Expose `tenant_type` in read/write serializer

## Technical Notes

**Migration DDL (RunSQL steps inside 0016):**
```sql
-- Step 1: Backfill customer_id on users
UPDATE user_auth_users SET customer_id = CAST(id AS VARCHAR) WHERE customer_id IS NULL;

-- Step 2: Backfill customer_id on tenants
UPDATE tenant_management_tenants SET customer_id = CAST(id AS VARCHAR) WHERE customer_id IS NULL;

-- Step 3: Add tenant_type column
ALTER TABLE tenant_management_tenants
  ADD COLUMN IF NOT EXISTS tenant_type VARCHAR(30) NOT NULL DEFAULT 'cloud';

-- Step 4: Verification marker
SELECT 'MIGRATION 0016 COMPLETE';
```

**Allowed `tenant_type` values:** `'cloud'` | `'vulnerability'` | `'secops'`

**Django model addition for `Tenant`:**
```python
TENANT_TYPE_CHOICES = [
    ('cloud', 'Cloud'),
    ('vulnerability', 'Vulnerability'),
    ('secops', 'SecOps'),
]
tenant_type = models.CharField(max_length=30, choices=TENANT_TYPE_CHOICES, default='cloud')
```

**Post-deploy manual SQL (run after verifying backfill — NOT in this migration):**
```sql
ALTER TABLE user_auth_users ALTER COLUMN customer_id SET NOT NULL;
ALTER TABLE tenant_management_tenants ALTER COLUMN customer_id SET NOT NULL;
```

**Verification command after deploy:**
```bash
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py shell -c \
  "from tenant_management.models import Tenant; \
   print('NULL customer_id:', Tenant.objects.filter(customer_id__isnull=True).count())"
# Expected: NULL customer_id: 0
```

**DB access pattern (RDS not public):**
```bash
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py migrate tenant_management 0016
kubectl logs -l app=cspm-backend -n threat-engine-engines | grep "MIGRATION 0016"
```

**grep check — no prohibited names:**
```bash
grep -r "organizations\|org_id" platform/cspm-backend/ --include="*.py" | grep -v ".pyc"
# Expected: no new hits in changed files
```

## Security Checklist

- [ ] `require_permission()` present on all new/modified endpoints (N/A — migration only, no endpoint changes in this story)
- [ ] `tenant_id` sourced from `X-Auth-Context` only (N/A — migration only)
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits in changed files
- [ ] Unit test: assert `Tenant.objects.first().tenant_type == 'cloud'` after migration
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s after rollout
- [ ] Post-deploy: curl gateway health-check 200
- [ ] Backfill verification query returns 0 NULL rows for both tables
