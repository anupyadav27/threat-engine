# Story: Auth-A1 — Django Migrations (DB Cleanup + customer_id + Group Tables)

## Status: ready

## Context

**CORRECT DESIGN (supersedes any ADR-007 reference to organizations table):**
- `customer_id = str(user.id)` of the founding user is the org key.
- There is NO `organizations` table. The `organizations` table (0 rows) is dropped by this migration.
- All tenants under one org share `tenants.customer_id = founder_user_id`.
- `UserAdminScope.scope_type = 'organization'`, `scope_id = customer_id`.

The migration `20260503_cspm_cleanup_and_org_foundation.sql` has already been written
and committed. This story applies it to RDS and updates Django ORM models to match.

The migration does:
1. Drops 17 dead tables (0 rows each) — onboarding_*, assets, organizations, agents, etc.
2. Removes legacy roles (landlord, super_landlord, tenant, customer_admin).
3. Seeds 4 new permissions: groups:read, groups:write, orgs:read, orgs:write.
4. Adds `tenant_type VARCHAR(50) DEFAULT 'cloud'` to `tenant_management_tenants`.
5. Adds `customer_id VARCHAR(255) NULL` to `tenant_management_tenants` and `user_auth_users`.
6. Adds `role_id FK` to `tenant_management_useraccountaccess`.
7. Creates 4 new group tables: `tenant_management_csmgroups`, `tenant_management_groupmembers`,
   `tenant_management_tenantgroupaccess`, `tenant_management_accountgroupaccess`.
8. Backfills `customer_id = id` on all existing users, `customer_id` on tenants from first org_admin.

`scope_resolver.py` line 104 has a logic bug: when `org_admin` has no `UserAdminScope` rows,
`org_ids` resolves to `None` (unrestricted) instead of `[]` (no access). This must be fixed in
this story (also tracked in B4, but the bug lives here).

**Points:** Medium (1–2 days). Pure migration apply + Django ORM model updates + one bug fix.

**Dependencies:** None. First story in the sprint. Blocks all other A, B, C, D stories.

---

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [x] Design  [x] Implementation  [ ] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [x] GV Govern  [x] ID Identify  [x] PR Protect  [ ] DE Detect  [ ] RS Respond  [ ] RC Recover

**CSA CCM v4 Domain(s)**
- IAM-01 (Identity and Access Management Policy), IAM-02 (User Access Provisioning),
  SEF-03 (Audit Logging), DSI-07 (Data Segregation)

---

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | `scope_resolver.py` line 104 bug | `org_admin` with no `UserAdminScope` rows gets `None` → unrestricted tenant list returned | Fix: return `[]` when `org_ids` is empty (not `None`) |
| Elevation of Privilege | `orgs:write` seeded but not assigned | Story seeds permission but does NOT assign to `org_admin` yet (B4 gate) | Permission assigned only after B4 boundary enforcement validated |
| Tampering | Migration 0013 (deferred NOT NULL) | `ALTER TABLE` locks if rows still NULL | Run NOT NULL step separately after verifying 0 NULL rows; documented as Step 7 in migration |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Privilege escalation | `org_admin` gets unrestricted tenant read | scope_resolver line 104 returns `None` for empty UserAdminScope | Fix returns `[]`; `None` is reserved for platform_admin only |

---

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078 | Valid Accounts (privilege abuse) | D3-UBA User Behavior Analytics | scope_resolver bug fixed; org_admin cannot get unrestricted access via empty scope |

---

## Acceptance Criteria (Functional)

1. Migration `20260503_cspm_cleanup_and_org_foundation.sql` applied to RDS. Verification:
   ```sql
   -- Should return 0 rows (all dead tables gone)
   SELECT table_name FROM information_schema.tables WHERE table_schema='public'
   AND table_name IN ('organizations','onboarding_tenants','assets','agents');
   -- Should return 0 rows (legacy roles gone)
   SELECT name FROM user_auth_roles WHERE name IN ('landlord','super_landlord','tenant','customer_admin');
   -- Should return 2 rows
   SELECT column_name FROM information_schema.columns
   WHERE table_name='tenant_management_tenants' AND column_name IN ('tenant_type','customer_id');
   -- Should return 0 rows (backfill complete)
   SELECT COUNT(*) FROM user_auth_users WHERE customer_id IS NULL;
   -- Should return 4 rows
   SELECT key FROM user_auth_permissions WHERE key IN ('groups:read','groups:write','orgs:read','orgs:write');
   ```

2. Django ORM models updated in `tenant_management/models.py`:
   - `Tenants` model: new fields `tenant_type = models.CharField(max_length=50, default='cloud')` and `customer_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)`
   - `UserAccountAccess` model: new field `role = models.ForeignKey('user_auth.Roles', null=True, on_delete=models.SET_NULL)`
   - New models: `CsmGroups`, `GroupMembers`, `TenantGroupAccess`, `AccountGroupAccess` matching group tables

3. Django ORM models updated in `user_auth/models.py`:
   - `Users` model: new field `customer_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)`

4. `scope_resolver.py` line 104 bug fixed:
   ```python
   # BEFORE (buggy):
   org_ids = UserAdminScope.objects.filter(...).values_list("scope_id", flat=True) or None
   # AFTER (correct):
   org_ids = list(
       UserAdminScope.objects.filter(user=user, scope_type="organization")
       .values_list("scope_id", flat=True)
   )
   if not org_ids:
       return []  # NOT None — None means unrestricted (platform_admin only)
   ```

5. `grep -r "organizations\|OrganizationUsers\|organization_id" platform/` returns 0 new hits in changed files.

6. Existing tenant creation (TenantViewSet) continues to work with `customer_id=NULL` until A2 deploys — no 500 errors.

---

## Acceptance Criteria (Security)

- [ ] `grep -r "organizations" platform/tenant_management/` returns 0 results after merge
- [ ] `scope_resolver.py`: empty `UserAdminScope` → `[]` not `None`; unit-tested
- [ ] `orgs:write` is seeded in permissions table but NOT yet assigned to `org_admin` role
- [ ] Migration apply command documented and verified against RDS

---

## Technical Notes

### Apply Migration

```bash
# Get cspm-backend pod (has access to cspm DB)
POD=$(kubectl get pods -n threat-engine-engines -l app=cspm-backend -o jsonpath='{.items[0].metadata.name}')

# Copy migration
kubectl cp /Users/apple/Desktop/threat-engine/shared/database/migrations/20260503_cspm_cleanup_and_org_foundation.sql \
  threat-engine-engines/$POD:/tmp/migration.sql

# Apply
kubectl exec -n threat-engine-engines $POD -- \
  psql -h $DB_HOST -U $DB_USER -d cspm -f /tmp/migration.sql

# Verify
kubectl exec -n threat-engine-engines $POD -- \
  psql -h $DB_HOST -U $DB_USER -d cspm -c \
  "SELECT COUNT(*) FROM user_auth_users WHERE customer_id IS NULL;"
# → should return 0
```

### New Django models (group tables)

File: `platform/cspm-backend/tenant_management/models.py`

```python
class CsmGroups(models.Model):
    id = models.CharField(max_length=255, primary_key=True, default=generate_uuid)
    customer_id = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    created_by = models.ForeignKey('user_auth.Users', null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tenant_management_csmgroups'
        unique_together = [('customer_id', 'name')]


class GroupMembers(models.Model):
    id = models.CharField(max_length=255, primary_key=True, default=generate_uuid)
    group = models.ForeignKey(CsmGroups, on_delete=models.CASCADE, related_name='members')
    user = models.ForeignKey('user_auth.Users', on_delete=models.CASCADE)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'tenant_management_groupmembers'
        unique_together = [('group', 'user')]


class TenantGroupAccess(models.Model):
    id = models.CharField(max_length=255, primary_key=True, default=generate_uuid)
    group = models.ForeignKey(CsmGroups, on_delete=models.CASCADE)
    tenant = models.ForeignKey(Tenants, on_delete=models.CASCADE)
    role = models.ForeignKey('user_auth.Roles', on_delete=models.RESTRICT)
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'tenant_management_tenantgroupaccess'
        unique_together = [('group', 'tenant')]


class AccountGroupAccess(models.Model):
    id = models.CharField(max_length=255, primary_key=True, default=generate_uuid)
    group = models.ForeignKey(CsmGroups, on_delete=models.CASCADE)
    tenant = models.ForeignKey(Tenants, on_delete=models.CASCADE)
    account_id = models.CharField(max_length=512)
    role = models.ForeignKey('user_auth.Roles', on_delete=models.RESTRICT)
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'tenant_management_accountgroupaccess'
        unique_together = [('group', 'tenant', 'account_id')]
```

### scope_resolver.py fix

File: `shared/auth/core/scope_resolver.py` (also used by: `platform/cspm-backend/`)

```python
# Around line 104 — find: org_ids = UserAdminScope...or None
# Replace with:
org_ids = list(
    UserAdminScope.objects.filter(user=user, scope_type="organization")
    .values_list("scope_id", flat=True)
)
# Empty list = this org_admin has no org scope assigned = no access
# NEVER use `or None` here — None signals platform_admin (unrestricted)
```

---

## Key Files

- `platform/cspm-backend/tenant_management/models.py` — add tenant_type, customer_id to Tenants, add 4 group models
- `platform/cspm-backend/user_auth/models.py` — add customer_id to Users
- `shared/auth/core/scope_resolver.py` — fix line 104 bug
- `shared/database/migrations/20260503_cspm_cleanup_and_org_foundation.sql` — apply to RDS

---

## Definition of Done

- [ ] Migration applied to RDS and all 6 verification queries pass
- [ ] Django ORM: Tenants, Users, UserAccountAccess models have new columns
- [ ] Django ORM: 4 new group models created and registered in admin
- [ ] `scope_resolver.py` bug fixed: empty UserAdminScope → returns `[]`
- [ ] Test: `test_scope_resolver_org_admin_no_scope_returns_empty`
- [ ] `grep -r "organizations\b" platform/tenant_management/ platform/user_auth/` returns 0 results
- [ ] cspm-backend pod restart clean (no ORM schema mismatch errors)
- [ ] bmad-security-reviewer: no BLOCKERs
