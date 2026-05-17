---
id: auth-B4
title: "org_admin org-boundary + remove developer bypass"
sprint: B
points: 3
depends_on: [auth-A1]
blocks: []
security_blocks: [BLOCK-07, BLOCK-11]
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

BLOCK-07 and BLOCK-11 from the security architect review. BLOCK-07: A `developer` role exists in the Django permission system that bypasses all RBAC checks — it was added as a convenience role during development. This bypass must be removed entirely. Any user currently assigned the `developer` role must be migrated to the appropriate production role (`org_admin` or `tenant_admin`). BLOCK-11: `org_admin` can currently read and modify tenants and cloud accounts across ALL customer orgs — there is no `customer_id`-based boundary check. This means an `org_admin` from one customer could manipulate another customer's data. This story enforces `customer_id` boundary at every Django view that `org_admin` can reach, and removes the developer bypass. Depends on auth-A1 because `customer_id` must be backfilled on all users before the boundary filter can safely be applied (NULL customer_id would fail the filter).

## Acceptance Criteria

- [ ] AC1 (BLOCK-07): The `developer` role and any associated permissions are deleted from the Django roles/permissions tables via a data migration.
- [ ] AC2 (BLOCK-07): Any RBAC check in `platform/cspm-backend/` that reads `role == 'developer'` or `user.is_developer` is removed.
- [ ] AC3 (BLOCK-07): Users previously assigned the `developer` role are migrated to `org_admin` (data migration — list affected users in migration SQL comment).
- [ ] AC4 (BLOCK-11): Every Django view callable by `org_admin` that queries `Tenant`, `CloudAccount`, or `User` objects applies `.filter(customer_id=request.user.customer_id)` before returning results.
- [ ] AC5 (BLOCK-11): `org_admin` attempting to access a tenant/account with a different `customer_id` receives HTTP 403 or 404 (not 200 with other org's data).
- [ ] AC6 (BLOCK-11): `platform_admin` (`l1` role) is exempt from the `customer_id` filter and can still read/write across all orgs.
- [ ] AC7: A `DjangoRolePermission` mixin or utility function `enforce_org_boundary(user, queryset)` is created and applied uniformly — not duplicated per-view.
- [ ] AC8: The post-deploy SQL to grant `org_admin` `orgs:write` and `users:write` permissions is noted in the story (not applied here — manual step after B4 confirmed working).
- [ ] AC9: Unit tests: `org_admin` queryset returns only same-customer tenants; cross-customer access returns 403; developer role does not exist; platform_admin sees all.
- [ ] AC10: `grep -r "developer" platform/cspm-backend/ --include="*.py"` returns zero hits in production code paths (comments allowed).

## Key Files

- `platform/cspm-backend/user_auth/models.py` — Remove `developer` role references
- `platform/cspm-backend/user_auth/drf_permissions.py` — Remove developer bypass in permission checks
- `platform/cspm-backend/tenant_management/views.py` — Apply `enforce_org_boundary()` to all querysets
- `platform/cspm-backend/user_auth/views/` — Apply boundary to user-related views
- `platform/cspm-backend/user_auth/migrations/0017_remove_developer_role.py` — Data migration to delete developer role and reassign users
- `platform/cspm-backend/utils/rbac.py` (create) — `enforce_org_boundary(user, queryset)` utility

## Technical Notes

**Find all developer role references:**
```bash
grep -rn "developer\|is_developer\|role.*developer\|developer.*role" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"
```

**Data migration to remove developer role:**
```python
# 0017_remove_developer_role.py
from django.db import migrations

def remove_developer_role(apps, schema_editor):
    Role = apps.get_model('user_auth', 'Role')  # adjust model name as needed
    UserRole = apps.get_model('user_auth', 'UserRole')

    try:
        dev_role = Role.objects.get(name='developer')
        # Migrate affected users to org_admin
        org_admin = Role.objects.get(name='org_admin')
        UserRole.objects.filter(role=dev_role).update(role=org_admin)
        dev_role.delete()
    except Role.DoesNotExist:
        pass  # already removed

class Migration(migrations.Migration):
    dependencies = [('user_auth', '0016_cleanup_customer_id')]  # adjust as needed
    operations = [migrations.RunPython(remove_developer_role, migrations.RunPython.noop)]
```

**enforce_org_boundary utility:**
```python
# utils/rbac.py
def enforce_org_boundary(user, queryset):
    """
    Filter queryset by customer_id unless user is platform_admin.
    Raises ValueError if user.customer_id is None (A1 backfill must be complete).
    """
    if user.has_perm('platform:admin'):
        return queryset
    if not user.customer_id:
        raise PermissionError("User has no customer_id — migration A1 incomplete")
    return queryset.filter(customer_id=user.customer_id)
```

**Apply in views:**
```python
def get_queryset(self):
    return enforce_org_boundary(self.request.user, Tenant.objects.all())
```

**Post-deploy manual SQL (RUN AFTER B4 CONFIRMED WORKING — not in migration):**
```sql
INSERT INTO role_permissions (id, role_id, permission_id, created_at, updated_at)
SELECT gen_random_uuid()::text, r.id, p.id, NOW(), NOW()
FROM roles r, permissions p
WHERE r.name = 'org_admin' AND p.key IN ('orgs:write', 'users:write')
ON CONFLICT DO NOTHING;
```

**Prerequisite check before deploying B4:**
```sql
SELECT COUNT(*) FROM user_auth_users WHERE customer_id IS NULL;
-- Must return 0 (A1 migration must be complete)
```

## Security Checklist

- [ ] Developer role completely removed — no bypass path remains
- [ ] `customer_id` filter sourced from authenticated user object, not request body or query param
- [ ] `platform_admin` bypass is role-based, not a header that can be spoofed
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "developer" platform/cspm-backend/ --include="*.py"` — zero hits in non-comment code
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits
- [ ] Unit tests: org boundary, platform_admin bypass, developer role removed
- [ ] bmad-security-reviewer: no BLOCKERs (BLOCK-07 and BLOCK-11 resolved)
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: org_admin can only see their own tenants; platform_admin sees all