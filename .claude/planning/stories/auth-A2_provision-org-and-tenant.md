# Story: Auth-A2 — provision_tenant_for_new_user() replaces provision_first_tenant()

## Status: ready

## Context

**CORRECT DESIGN:**
- `customer_id = str(user.id)` is the org key set at signup for every founding user.
- There is NO `Organizations` model. ADR-007 (organizations table) is superseded.
- `UserAdminScope(scope_type='organization', scope_id=customer_id)` is how org_admin scope is recorded.
- All tenants created by this user inherit `customer_id = str(user.id)`.

`provision_first_tenant()` in `tenant_utils.py` creates a `Tenant` and syncs it to the onboarding engine inside `transaction.atomic()`. This story replaces it with `provision_tenant_for_new_user()` that:
1. Sets `user.customer_id = str(user.id)` on the founding user.
2. Creates the first `Tenant` with `customer_id = str(user.id)` and `tenant_type = 'cloud'`.
3. Creates `TenantUsers(user, tenant, role=org_admin)`.
4. Creates `UserAdminScope(user, scope_type='organization', scope_id=str(user.id))`.
5. Does NOT call `_sync_tenant_to_onboarding` (HTTP call moved to Celery task in A-3).

Call sites to update: `SignupView`, `GoogleCallbackView`, `MicrosoftCallbackView`, `OIDCCallbackView`.

`signals.py` currently passes `org_id=str(instance.id)` (tenant.id). After this story, signals pass `customer_id=str(user.id)`. The billing task reads `customer_id` from the user on the tenant, not a separate org UUID.

**Points:** Medium (1–2 days). Logic change in tenant_utils.py + 4 call-site updates + signals.py.

**Dependencies:** Auth-A1 must deploy first (`customer_id` column must exist on `user_auth_users` and `tenant_management_tenants`).

---

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [ ] DE Detect  [x] RS Respond  [x] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: IAM-01 (Identity and Access Management Policy), IAM-02 (User Access Provisioning),
  BCR-11 (Business Continuity — broken signup state recovery)

---

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | `provision_tenant_for_new_user()` | Attacker passes crafted `company_name` with SQL or shell metacharacters | `company_name` is ORM-parametrized; slug via `django.utils.text.slugify()` |
| Tampering | Slug collision | Attacker registers slug matching a reserved name (api, admin, www) | Reserved slug list check; collision → append 8-char `str(user.id)[:8]` suffix |
| Info Disclosure | Exception logging | Exception might log `company_name` or email | Log only `user.id` in exception path; never log email |
| Elevation of Privilege | `UserAdminScope` creation | `scope_type` comes from user input | Hardcoded `scope_type="organization"` in function body — no user input accepted |
| DoS | Signup endpoint | Rapid signups → rapid DB row creation | Rate limiting on SignupView (B1, BLOCK-02) |

---

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1136.003 | Create Cloud Account | D3-ACH Account Creation Hardening | `customer_id = str(user.id)` set atomically; rate limit on signup (B1) |
| T1078 | Valid Accounts | D3-UBA User Behavior Analytics | Every signup emits `log_auth_event("signup.local")` with `customer_id` |

---

## Acceptance Criteria (Functional)

1. New function `provision_tenant_for_new_user(user, company_name)` in `tenant_utils.py` creates inside ONE `transaction.atomic()`:
   - Sets `user.customer_id = str(user.id)`, saves user.
   - `Tenants.objects.create(name=company_name, slug=slug, customer_id=str(user.id), tenant_type='cloud', status='provisioning')`
   - `TenantUsers.objects.create(user=user, tenant=tenant, role=org_admin_role)`
   - `UserAdminScope.objects.create(user=user, scope_type='organization', scope_id=str(user.id))`
   - Returns `tenant` object.
   - Does NOT call `_sync_tenant_to_onboarding` or any HTTP call.

2. Slug collision handling: if slug already exists, retry with `f"{slug}-{str(user.id)[:8]}"` exactly once. If still collides, raise `TenantSlugCollisionError`.

3. `SignupView`, `GoogleCallbackView`, `MicrosoftCallbackView`, `OIDCCallbackView` all call `provision_tenant_for_new_user()` instead of `provision_first_tenant()`.

4. `signals.py` billing signal: `instance.customer_id` (from `Tenants.customer_id`) replaces any `instance.org.id` reference. The Celery task signature becomes `provision_billing_trial.delay(customer_id=str(tenant.customer_id))`.

5. `provision_first_tenant()` is deleted from `tenant_utils.py`. `grep -r "provision_first_tenant" platform/` returns 0 results.

6. After signup, a user row in `user_auth_users` has `customer_id = str(user.id)` (non-null).

7. After signup, the tenant row in `tenant_management_tenants` has `customer_id = str(user.id)` (same value).

8. Log event emitted: `log_auth_event("signup.provision", user_id=str(user.id), customer_id=str(user.id))`.

---

## Acceptance Criteria (Security)

- [ ] `provision_tenant_for_new_user()`: no HTTP calls inside `transaction.atomic()`
- [ ] `scope_type` hardcoded as `"organization"` — never taken from request body
- [ ] `customer_id` comes from `str(user.id)` server-side — never from request params
- [ ] `log_auth_event("signup.provision")` called with only `user_id` and `customer_id` (no email, no password)
- [ ] `grep -r "provision_first_tenant\|org\.id\|organization_id" platform/` returns 0 results in changed files

---

## Technical Notes

### New `provision_tenant_for_new_user()` — tenant_utils.py

```python
from django.db import transaction
from django.utils.text import slugify
from user_auth.models import Users, UserAdminScope
from tenant_management.models import Tenants, TenantUsers

RESERVED_SLUGS = frozenset(["api", "admin", "www", "app", "auth", "login", "signup",
                              "static", "assets", "help", "support", "billing"])


def provision_tenant_for_new_user(user: Users, company_name: str) -> Tenants:
    """Create first tenant for a founding user. Sets customer_id = str(user.id)."""
    base_slug = slugify(company_name)[:50]
    if base_slug in RESERVED_SLUGS:
        base_slug = f"{base_slug}-{str(user.id)[:8]}"

    with transaction.atomic():
        # 1. Set customer_id on the founding user
        user.customer_id = str(user.id)
        user.save(update_fields=["customer_id"])

        # 2. Create tenant
        slug = base_slug
        if Tenants.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{str(user.id)[:8]}"
            if Tenants.objects.filter(slug=slug).exists():
                raise TenantSlugCollisionError(f"Slug {slug!r} already taken")

        tenant = Tenants.objects.create(
            name=company_name,
            slug=slug,
            customer_id=str(user.id),
            tenant_type="cloud",
            status="provisioning",
        )

        # 3. Assign org_admin role on this tenant
        org_admin_role = Roles.objects.get(name="org_admin")
        TenantUsers.objects.create(user=user, tenant=tenant, role=org_admin_role)

        # 4. Grant org-level admin scope
        UserAdminScope.objects.create(
            user=user,
            scope_type="organization",
            scope_id=str(user.id),  # customer_id IS the scope_id
        )

    log_auth_event("signup.provision",
                   user_id=str(user.id),
                   customer_id=str(user.id),
                   tenant_id=str(tenant.id))
    return tenant
```

### Call-site change (all 4 auth views)

```python
# Before:
tenant = provision_first_tenant(user, company_name=data.get("company_name", "My Organization"))
# After:
tenant = provision_tenant_for_new_user(user, company_name=data.get("company_name", "My Organization"))
```

### signals.py billing fix

```python
# Before:
provision_billing_trial.delay(org_id=str(instance.id))
# After (use customer_id which is already on the tenant):
provision_billing_trial.delay(customer_id=str(instance.customer_id))
```

---

## Key Files

- `platform/cspm-backend/user_auth/utils/tenant_utils.py` — complete replacement of `provision_first_tenant()`
- `platform/cspm-backend/user_auth/views/local_auth.py` — update SignupView call
- `platform/cspm-backend/user_auth/views/google_auth.py` — update GoogleCallbackView
- `platform/cspm-backend/user_auth/views/microsoft_auth.py` — update MicrosoftCallbackView (if exists)
- `platform/cspm-backend/user_auth/views/oidc_auth.py` — update OIDCCallbackView (if exists)
- `platform/cspm-backend/tenant_management/signals.py` — fix billing signal

---

## Definition of Done

- [ ] `provision_tenant_for_new_user()` creates user.customer_id + tenant + TenantUsers + UserAdminScope in one transaction
- [ ] No HTTP calls inside `transaction.atomic()`
- [ ] All 4 auth view call-sites updated
- [ ] `provision_first_tenant` deleted; grep returns 0 results
- [ ] `signals.py` uses `customer_id` not `org.id`
- [ ] Test: `test_provision_tenant_creates_customer_id_on_user`
- [ ] Test: `test_provision_tenant_creates_useradminscope_with_org_scope`
- [ ] Test: `test_provision_tenant_slug_collision_appends_user_id_suffix`
- [ ] Test: `test_provision_tenant_no_http_call_inside_transaction`
- [ ] bmad-security-reviewer: no BLOCKERs
