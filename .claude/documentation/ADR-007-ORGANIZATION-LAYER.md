# ADR-007: Organization Layer for CSPM Platform

**Status:** Approved  
**Date:** 2026-05-03  
**Replaces:** N/A — additive change

---

## 1. Context

Current top-level entity is `Tenant`. Desired hierarchy:

```
Organization  ← created on self-service signup (org_admin)
  └── Tenant  ← workspace/environment ("Production", "Dev")
        └── Cloud Account
              └── Scan Run → Findings
```

The codebase already anticipated this:
- `shared/auth/core/models.py`: `AuthContext.org_ids` field exists (unpopulated)
- `shared/auth/core/scope_resolver.py` line 90: dead query `Tenants.objects.filter(organization_id__in=org_ids)` — column doesn't exist yet
- `scope_resolver.py` line 59: imports `UserAdminScope` — model does not exist (import error)
- Billing engine already uses `org_id` (today = `tenant.id`, post-migration = real `org.id`)

---

## 2. Decision: Option A — New `organizations` Table, Engines Stay on `tenant_id`

All 20+ scanning engines remain unchanged. `org_id` lives only in Django platform DB, onboarding engine DB, and billing engine DB.

**Rejected:** Option B (merge Org+Tenant into hierarchical model) — blast radius touches every engine's DB schema and every `WHERE tenant_id = $1` query. Unacceptable.

---

## 3. Django Schema Changes

### New Model: `Organizations`
File: `platform/cspm-backend/tenant_management/models.py`

```python
class Organizations(models.Model):
    id          = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    name        = models.CharField(max_length=255)
    slug        = models.SlugField(max_length=100, unique=True)
    status      = models.CharField(max_length=50, default='active')
    billing_customer_id = models.CharField(max_length=255, blank=True, null=True)
    created_by  = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)
    class Meta:
        db_table = 'organizations'
```

### Modify `Tenants` — Add `org_id` FK (nullable → NOT NULL after backfill)

```python
org = models.ForeignKey(Organizations, on_delete=models.PROTECT, null=True,
                        db_column='organization_id', related_name='tenants')
```

### New Model: `OrganizationUsers`

```python
class OrganizationUsers(models.Model):
    id      = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    org     = models.ForeignKey(Organizations, on_delete=models.CASCADE)
    user    = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role    = models.ForeignKey('user_auth.Roles', on_delete=models.PROTECT)
    is_active = models.BooleanField(default=True)
    class Meta:
        db_table = 'organization_users'
        unique_together = ('org', 'user')
```

### New Model: `UserAdminScope` (referenced in scope_resolver.py but missing)
File: `platform/cspm-backend/user_auth/models.py`

```python
class UserAdminScope(models.Model):
    id         = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user       = models.ForeignKey('Users', on_delete=models.CASCADE, related_name='admin_scopes')
    scope_type = models.CharField(max_length=50)   # "organization" | "tenant" | "account"
    scope_id   = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        db_table = 'user_admin_scope'
        unique_together = ('user', 'scope_type', 'scope_id')
```

---

## 4. RBAC Changes

`org_admin` role already seeded in migration 0009 with `scope_level='organization'`, `level=2`. No new role needed.

New permissions to add in migration 0011:
- `orgs:read` → platform_admin, org_admin, tenant_admin
- `orgs:write` → platform_admin, org_admin

| Role | Creates Tenants | Invite Users | Cross-Tenant View |
|------|----------------|--------------|-------------------|
| platform_admin | Any org | Any | All |
| org_admin | Within their org | Within their org | Within their org only |
| tenant_admin | No | Within tenant | No |
| analyst/viewer | No | No | No |

**CRITICAL:** `org_admin` write permissions (`users:write`, `settings:write`) must NOT go live until the `Organization` model is in place and org-boundary enforcement is implemented at the view layer.

---

## 5. Signup Flow

`provision_first_tenant()` → replace with `provision_org_and_tenant()`:

```
1. POST /api/auth/signup/ → create User
2. INSERT INTO organizations (id, name, slug, created_by)
3. INSERT INTO tenants (id, name, org_id="Default")
4. INSERT INTO organization_users (org, user, role=org_admin)
5. INSERT INTO user_admin_scope (user, scope_type="organization", scope_id=org.id)
6. Commit Django transaction
7. Async: sync_tenant_to_onboarding.apply_async(...)  ← outside atomic()
8. Async: provision_billing_trial.apply_async(org_id=org.id)
9. Return 201 → frontend redirects to /onboarding
```

Same replacement for Google OAuth (`google_auth.py`), Microsoft OAuth, OIDC callbacks.

Slug collision: auto-suffix with first 8 chars of `org.id` on `IntegrityError`, retry once.

---

## 6. Auth Context Changes

`GET /api/auth/me/` adds `organizations[]` array alongside existing `tenants[]` (kept for backward compat):

```json
{
  "organizations": [
    {
      "org_id": "...",
      "org_name": "Acme Corp",
      "org_slug": "acme-corp",
      "role": "org_admin",
      "tenants": [{ "tenant_id": "...", "tenant_name": "Default", ... }]
    }
  ],
  "tenants": [...]  // flat list, kept unchanged
}
```

Frontend `AuthContext` needs: `selectedOrg`, `selectedTenant`, org/tenant switcher component.  
Gateway `AuthMiddleware` — no change (still reads `engine_tenant_id` from scope_cache).

---

## 7. Migration Strategy (Zero-Downtime)

**Migration 0011** — Create `organizations`, `organization_users`, `user_admin_scope` tables + seed permissions. Fix `UserAdminScope` import error in `scope_resolver.py`.

**Migration 0012** — `ALTER TABLE tenants ADD COLUMN organization_id TEXT NULL REFERENCES organizations(id)`.

**Backfill script** (run after 0012 deploys, before 0013):
```sql
INSERT INTO organizations(id, name, slug, status, created_at, updated_at)
SELECT id,
       name,
       lower(regexp_replace(name, '[^a-z0-9]+', '-', 'gi')) || '-' || substring(id::text, 1, 8),
       status, created_at, updated_at
FROM tenants WHERE organization_id IS NULL
ON CONFLICT (id) DO NOTHING;

UPDATE tenants SET organization_id = id WHERE organization_id IS NULL;
```

**Migration 0013** — `ALTER TABLE tenants ALTER COLUMN organization_id SET NOT NULL`.

**Onboarding DB migration** (separate):
```sql
ALTER TABLE tenants ADD COLUMN org_id VARCHAR(255) NULL;
UPDATE tenants SET org_id = tenant_id;
```

---

## 8. Onboarding Engine Changes

`engines/onboarding/database/models.py` — add `org_id = Column(String(255), nullable=True, index=True)` to `Tenant`.

`_sync_tenant_to_onboarding` payload — add `"org_id": org_id`.

`ScanRun` and `CloudAccount` — no changes.

---

## 9. Billing Engine Impact

Billing already uses `org_id` as its primary key. Today `org_id = tenant.id`. Post-migration: `signals.py` must pass `org_id=str(instance.org.id)` (real org UUID) for new tenants. Existing billing records keyed by old `tenant.id` remain valid because backfill sets `org.id = tenant.id` (1:1).

---

## 10. What Does NOT Change

All 20+ scanning engines, their DB schemas, Argo pipeline, BFF view handlers, Gateway AuthMiddleware, `AuthContext` dataclass, `UserSessions.scope_cache` structure, K8s manifests for scanning engines.

---

## 11. New API Endpoints (Django)

| Method | Path | Permission |
|--------|------|-----------|
| POST | `/api/v1/organizations/` | signup flow / `orgs:write` |
| GET | `/api/v1/organizations/` | `orgs:read` |
| GET | `/api/v1/organizations/{org_id}/` | `orgs:read` |
| PATCH | `/api/v1/organizations/{org_id}/` | `orgs:write` |
| GET | `/api/v1/organizations/{org_id}/tenants/` | `tenants:read` |
| POST | `/api/v1/organizations/{org_id}/tenants/` | `orgs:write` |
| POST | `/api/v1/organizations/{org_id}/members/` | `users:write` |
| GET | `/api/v1/organizations/{org_id}/members/` | `users:read` |

---

## 12. Implementation Order

1. Migration 0011 (org tables + permissions + fix UserAdminScope import)
2. Migration 0012 (nullable org_id on tenants)
3. `provision_org_and_tenant()` replacing `provision_first_tenant()`
4. `MeView` — add `organizations[]` to response
5. `signals.py` — use `instance.org.id` for billing
6. Backfill script on prod
7. Migration 0013 (NOT NULL)
8. Onboarding engine — add `org_id` column + accept in POST /tenants
9. Organization API views
10. Frontend — org switcher, AuthContext `selectedOrg`/`selectedTenant`

---

## 13. Key Risks

| Risk | Mitigation |
|------|-----------|
| Backfill during live signups | Run during low-traffic; 0013 only after backfill verified |
| `scope_resolver.py` line 104 logic bug — `org_admin` with empty `org_ids` gets `None` (unrestricted) instead of `[]` | Fix conditional; ensure every org_admin has a `UserAdminScope` row |
| Billing `org_id` drift | Backfill sets `org.id = tenant.id` for all existing rows — consistent |
| Async tenant sync failure | Dead-letter queue + `tenant.status = 'sync_failed'` + admin alert |
