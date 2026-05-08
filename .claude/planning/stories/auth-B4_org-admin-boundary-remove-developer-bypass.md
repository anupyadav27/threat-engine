# Story: Auth-B4 — org_admin Org-Boundary Enforcement + Remove Developer Bypass

## Status: ready

## Context

`build_tenant_query()` in `tenant_management/filters.py` has a `user_has_developer_role()`
check: if a user's role name is "developer" (case-insensitive), they get ALL tenants with
no scoping. This bypass must be removed before any `org_admin` write permissions go live
(BLOCK-07, ATT&CK T1078).

**CORRECT ORG MODEL:**  
`customer_id` = `str(user.id)` of the founding user. This is the org key.
All tenants under one org have `tenants.customer_id = founder_user_id`.
There is NO `organizations` table and NO `organization_id` column on tenants.
`UserAdminScope.scope_type = 'organization'`, `scope_id = customer_id`.

The `org_admin` path in `build_tenant_query` does not yet exist — it currently falls
through to the generic `tenant_users` filter which is correct for `tenant_admin` and
`analyst` but does NOT enforce the org boundary. An `org_admin` invited to a tenant in a
foreign org could read all of that foreign org's tenants (BLOCK-11).

`TenantIDPConfigListCreateView.post()` does not verify that the `tenant_id` in the body
belongs to the requester's org — only that the requester is a member of that tenant.

`accept_invite_membership()` assigns the invited role directly without detecting
cross-org invite scenarios.

`scope_resolver.py` line 104 has a logic bug: if `org_admin` has no `UserAdminScope`
rows, `org_ids` resolves to `None` (unrestricted) instead of `[]` (no access).

**Dependencies:** Auth-A1 must be deployed first (adds `tenant_type` + `customer_id`
columns). Auth-B3 must be deployed (CookieTokenAuthentication needed for enforcement).

**Points:** Medium (1–2 days). Three files changed, no new DB tables.

---

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [x] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [x] GV Govern  [ ] ID Identify  [x] PR Protect  [ ] DE Detect  [ ] RS Respond  [ ] RC Recover

**CSA CCM v4 Domain(s)**
- IAM-01 (Identity and Access Management Policy), IAM-02 (User Access Provisioning),
  IAM-07 (Least Privilege)

---

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Elevation of Privilege | `user_has_developer_role` bypass | User with role named "developer" gets ALL tenants unscoped | Remove function entirely |
| Elevation of Privilege | `org_admin` cross-org read | org_admin of Org A invited to one tenant in Org B → `build_tenant_query` returns all of Org B's tenants | Add `customer_id` filter for org_admin path |
| Spoofing | `TenantIDPConfigListCreateView` cross-org | org_admin of Org A posts with `tenant_id` from Org B → creates IDP config for foreign org | Verify `tenant.customer_id == request.user.customer_id` |
| Elevation of Privilege | Cross-org invite role escalation | org_admin accepts invite to foreign org tenant → retains high role | Cap role at `viewer` on cross-org invite |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Privilege escalation | Unrestricted tenant access | Create account → get "developer" role assigned → all tenants exposed | Remove bypass entirely |
| Cross-org data exfil | Read foreign org's tenants | org_admin A invited to one tenant in Org B → GET /api/v1/tenants/ returns all Org B | `build_tenant_query`: filter org_admin by `customer_id = user.customer_id` |

---

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1078 | Valid Accounts (privilege abuse) | D3-UBA User Behavior Analytics | developer bypass removed; org_admin scoped to own customer_id |
| T1548 | Abuse Elevation Control Mechanism | D3-ACH Account Creation Hardening | Cross-org invite caps role at viewer |

---

## Acceptance Criteria (Functional)

1. `user_has_developer_role()` function is deleted from `tenant_management/filters.py`.
   All imports of this function are also removed. `grep -r "user_has_developer_role"
   platform/` returns no results.

2. `build_tenant_query()` gains an `org_admin` path keyed on `role.scope_level ==
   "organization"`. It filters tenants using `customer_id`:
   ```python
   if role.scope_level == "organization":
       if not hasattr(request.user, 'customer_id') or not request.user.customer_id:
           return Tenants.objects.none()
       return queryset.filter(customer_id=request.user.customer_id)
   ```
   Note: `customer_id` on `Tenants` is added by Auth-A1 migration 0012.

3. `build_tenant_query()` for `platform_admin` (`role.level == 1`): no filter — returns
   full queryset. This branch is explicit (not a fallthrough).

4. `build_tenant_query()` for `tenant_admin`, `analyst`, `viewer`: filter by
   `TenantUsers.objects.filter(user=user).values_list('tenant_id', flat=True)`.
   Unchanged from current behavior but made explicit.

5. If `user.customer_id` is empty (org_admin with no customer_id set — transition period):
   queryset returns `Tenants.objects.none()` — never unrestricted.

6. `scope_resolver.py` line 104 bug fixed: when `org_admin` has no `UserAdminScope` rows,
   `org_ids` returns `[]` not `None`. Explicit guard:
   ```python
   org_ids = list(UserAdminScope.objects.filter(
       user=user, scope_type="organization"
   ).values_list("scope_id", flat=True))
   if not org_ids:
       return []  # NOT None — None means unrestricted
   ```

7. `TenantIDPConfigListCreateView.post()`: after the tenant membership check, add:
   ```python
   tenant_obj = Tenants.objects.get(id=tenant_id)
   if str(tenant_obj.customer_id) != str(request.user.customer_id):
       return JsonResponse({"message": "Forbidden"}, status=403)
   ```
   This check runs ONLY for `org_admin`. `platform_admin` is exempt.

8. `accept_invite_membership()` in `tenant_utils.py`: detect cross-org invite:
   ```python
   invite_customer_id = str(invite.tenant.customer_id) if invite.tenant.customer_id else None
   user_customer_id = str(user.customer_id) if user.customer_id else None
   is_cross_org = (invite_customer_id and user_customer_id and
                   invite_customer_id != user_customer_id)
   if is_cross_org:
       role = _get_viewer_role()
       log_auth_event("invite.cross_org_capped", user_id=str(user.id),
                      from_customer=user_customer_id, to_customer=invite_customer_id)
   ```
   Function returns `{"cross_org_invite": is_cross_org}` (callers can ignore return value).

9. `org_admin` write permissions (`users:write`, `settings:write`, `orgs:write`) are NOT
   activated by this story. They require a post-deploy SQL (documented below) applied
   only after full validation of org-boundary enforcement.

---

## Acceptance Criteria (Security — must pass bmad-security-reviewer)

- [ ] `grep -r "user_has_developer_role" platform/` returns no results after merge
- [ ] `build_tenant_query` org_admin path: `customer_id` comes from `request.user`
      (server-side DB value) — NOT from query params or request body
- [ ] `build_tenant_query` platform_admin: explicit `role.level == 1` check — no role
      name string comparison (name can change; level is authoritative)
- [ ] Empty `customer_id` or missing UserAdminScope: `Tenants.objects.none()` — tested
- [ ] `TenantIDPConfigListCreateView` check: `tenant_obj.customer_id` from DB, not body
- [ ] `is_cross_org` logged via `log_auth_event("invite.cross_org_capped", ...)`
- [ ] No plaintext credentials in logs
- [ ] All new DB queries scoped by `user.customer_id` — no unbounded scans
- [ ] BLOCK-07 and BLOCK-11 marked closed

---

## Technical Notes

### `tenant_management/filters.py` — complete rewrite

```python
from django.db.models import Q
from .models import Tenants

ALLOWED_FILTERS = {"status", "plan", "region", "tenant_type"}
SEARCH_SUFFIX = "_search"
ALLOWED_LOOKUPS = {"iexact", "icontains", "istartswith", "gte", "lte", "gt", "lt"}


def build_tenant_query(params, user=None):
    base_query = Q()

    for param in ALLOWED_FILTERS:
        if param in params and params[param]:
            base_query &= Q(**{f"{param}__iexact": str(params[param]).strip()})

    for param, value in params.items():
        if param.endswith(SEARCH_SUFFIX) and value:
            field = param[: -len(SEARCH_SUFFIX)]
            if hasattr(Tenants, field):
                base_query &= Q(**{f"{field}__icontains": str(value).strip()})

    queryset = Tenants.objects.filter(base_query)

    if not user or not user.is_authenticated:
        return Tenants.objects.none()

    from user_auth.models import UserRoles

    primary_role = (
        UserRoles.objects.filter(user=user)
        .select_related("role")
        .order_by("role__level")
        .first()
    )
    if not primary_role:
        return Tenants.objects.none()

    role = primary_role.role

    # platform_admin — unrestricted
    if role.level == 1:
        return queryset

    # org_admin — restrict to own customer_id
    if role.scope_level == "organization":
        customer_id = getattr(user, 'customer_id', None)
        if not customer_id:
            return Tenants.objects.none()
        return queryset.filter(customer_id=customer_id)

    # tenant_admin, analyst, viewer — restrict to assigned tenants
    from tenant_management.models import TenantUsers
    tenant_ids = TenantUsers.objects.filter(user=user).values_list('tenant_id', flat=True)
    return queryset.filter(id__in=tenant_ids)
```

### `scope_resolver.py` — fix line 104 logic bug

File: `shared/auth/core/scope_resolver.py`

Current (buggy — org_admin with no rows gets None = unrestricted):
```python
org_ids = UserAdminScope.objects.filter(...).values_list("scope_id", flat=True) or None
```

Fix:
```python
org_ids = list(
    UserAdminScope.objects.filter(user=user, scope_type="organization")
    .values_list("scope_id", flat=True)
)
# empty list = no org access; None was a bug (meant unrestricted)
```

### Post-deploy SQL — enable org_admin writes (manual, after validation)

```sql
-- Run ONLY after B-4 is deployed and org-boundary confirmed working in production
INSERT INTO role_permissions (id, role_id, permission_id, created_at, updated_at)
SELECT gen_random_uuid()::text, r.id, p.id, NOW(), NOW()
FROM roles r, permissions p
WHERE r.name = 'org_admin' AND p.key IN ('orgs:write', 'users:write')
ON CONFLICT DO NOTHING;
```

Document this as a post-deploy manual step in the PR description, NOT in a migration.

---

## Key Files

- `platform/cspm-backend/tenant_management/filters.py` — complete rewrite
- `platform/cspm-backend/tenant_management/views.py` — TenantIDPConfigListCreateView.post
- `platform/cspm-backend/user_auth/utils/tenant_utils.py` — accept_invite_membership
- `shared/auth/core/scope_resolver.py` — line 104 logic bug fix

---

## Definition of Done

- [ ] `grep -r "user_has_developer_role" platform/` returns no results
- [ ] Test: `test_build_tenant_query_org_admin_own_customer_id` — only own org's tenants returned
- [ ] Test: `test_build_tenant_query_org_admin_empty_customer_id_returns_none`
- [ ] Test: `test_build_tenant_query_platform_admin_unrestricted`
- [ ] Test: `test_build_tenant_query_tenant_admin_own_tenants_only`
- [ ] Test: `test_accept_invite_cross_org_caps_to_viewer`
- [ ] Test: `test_idp_create_cross_org_tenant_forbidden`
- [ ] Test: `test_scope_resolver_org_admin_no_scope_returns_empty_not_none`
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] BLOCK-07 and BLOCK-11 marked closed
- [ ] Post-deploy SQL for `orgs:write` assignment documented in PR description
