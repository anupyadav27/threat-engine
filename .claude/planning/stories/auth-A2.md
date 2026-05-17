---
id: auth-A2
title: "provision_tenant_for_new_user() replaces provision_first_tenant()"
sprint: A
points: 2
depends_on: [auth-A1]
blocks: [auth-A3, onboarding-D2]
security_blocks: []
nist_csf: GV
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

The Django platform has a function `provision_first_tenant()` in `platform/cspm-backend/services/provisioning.py` (or equivalent location) that is called after user signup. It provisions a default tenant for the new user. This function does not set `customer_id` on the user or the tenant, does not pass `tenant_type`, and is not async-safe for Celery. This story renames it to `provision_tenant_for_new_user()`, adds `customer_id` generation and assignment, adds `tenant_type` parameter, and makes it safe to call from the invite acceptance flow. The old function name must be replaced everywhere it is called (grep for callers first). Downstream story auth-A3 wires the async Celery sync.

## Acceptance Criteria

- [ ] AC1: Function `provision_tenant_for_new_user(user, tenant_type='cloud')` exists in `platform/cspm-backend/services/provisioning.py`.
- [ ] AC2: Function generates a `customer_id` string (`f"cust_{uuid4().hex[:12]}"`) if `user.customer_id` is not already set and saves it to `user_auth_users`.
- [ ] AC3: The provisioned `Tenant` object has `customer_id` matching the user's `customer_id`.
- [ ] AC4: The provisioned `Tenant` object has `tenant_type` set to the value passed in (default `'cloud'`).
- [ ] AC5: Old function name `provision_first_tenant()` does not appear anywhere in the codebase after this story (grep check).
- [ ] AC6: All callers of the old function are updated to call `provision_tenant_for_new_user()` with correct arguments.
- [ ] AC7: Function is transaction-safe — if tenant creation fails, `customer_id` is not persisted on the user.
- [ ] AC8: Function returns a dict `{"customer_id": str, "tenant_id": str, "tenant_type": str}` for use by downstream callers.
- [ ] AC9: Unit tests cover: normal provisioning, idempotent call (user already has customer_id), and failure rollback.

## Key Files

- `platform/cspm-backend/services/provisioning.py` — Primary file: rename function, add customer_id logic
- `platform/cspm-backend/user_auth/views/` — Update all callers of the old function name
- `platform/cspm-backend/user_auth/signals.py` — Update if `provision_first_tenant` is called in post-save signal

## Technical Notes

**Function signature:**
```python
from uuid import uuid4
from django.db import transaction

def provision_tenant_for_new_user(user, tenant_type: str = 'cloud') -> dict:
    """
    Provision a customer_id and initial Tenant for a newly created user.
    Idempotent: if user.customer_id already set, uses existing value.
    Returns: {"customer_id": str, "tenant_id": str, "tenant_type": str}
    """
    with transaction.atomic():
        if not user.customer_id:
            user.customer_id = f"cust_{uuid4().hex[:12]}"
            user.save(update_fields=['customer_id'])

        tenant = Tenant.objects.create(
            name=f"{user.email.split('@')[0]}-default",
            customer_id=user.customer_id,
            tenant_type=tenant_type,
        )
        return {
            "customer_id": user.customer_id,
            "tenant_id": str(tenant.id),
            "tenant_type": tenant_type,
        }
```

**Find all callers:**
```bash
grep -r "provision_first_tenant" /Users/apple/Desktop/threat-engine/platform/ --include="*.py"
```

**customer_id format:** `cust_` + 12 hex chars from UUID4. Example: `cust_3a4b5c6d7e8f`.

**`Tenant` model import path:** `from tenant_management.models import Tenant`

**No credentials in this story** — this is Django model logic only.

## Security Checklist

- [ ] `require_permission()` present on all new/modified endpoints (N/A — no new endpoints, internal function only)
- [ ] `tenant_id` sourced from `X-Auth-Context` only (N/A — Django provisioning, not FastAPI)
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "provision_first_tenant" platform/` returns zero hits
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits in changed files
- [ ] Unit tests added covering normal provisioning, idempotency, rollback
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: curl gateway health-check 200