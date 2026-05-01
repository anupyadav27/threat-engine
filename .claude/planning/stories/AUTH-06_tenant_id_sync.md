---
story_id: AUTH-06
title: Tenant ID sync — platform DB to onboarding engine
status: ready
sprint: auth-redesign-1
depends_on: []
blocks: []
sme: Python backend engineer (Django + FastAPI)
estimate: 1 day
---

# Story: Tenant ID Sync Between Platform DB and Onboarding Engine

## Context

**The bug**: When `provision_first_tenant()` creates a `Tenants` row in the Django/platform DB
(UUID `id`), nothing creates a matching row in the onboarding engine's `tenants` table.
The onboarding engine has its own `tenant_id` column. If the two UUIDs diverge, scan runs
fail because `scan_orchestration.tenant_id` (sourced from onboarding engine) does not match
any row in the platform DB.

**Current schema mismatch**:
- Platform: `tenants.id`, `tenants.name`, `tenants.contact_email`
- Onboarding engine: `tenants.tenant_id`, `tenants.customer_id`, `tenants.tenant_name`

The `customer_id` field in the onboarding DB has no direct analog in the platform DB.
By convention, `customer_id` = the `Users.id` of the tenant creator (the first admin).

This story:
1. Extends the onboarding engine `POST /api/v1/tenants/` to accept an explicit `tenant_id`
2. Modifies `provision_first_tenant()` to call the onboarding engine API after creating the Django tenant
3. Ensures the two DBs stay in sync with matching UUIDs

## Files to Create/Modify

**Onboarding engine** (`engines/onboarding/`):
- `engines/onboarding/api/cloud_accounts.py` — or whichever router handles tenant creation
- `engines/onboarding/models/tenant.py` — add `tenant_id` as optional field in `TenantCreate`
- `engines/onboarding/database/tenant_operations.py` — `create_tenant()` already accepts `tenant_id`; verify it does not auto-generate

**Platform** (`platform/cspm-backend/`):
- `platform/cspm-backend/user_auth/utils/tenant_utils.py` — `provision_first_tenant()` extended
- `platform/cspm-backend/config/settings.py` — add `ONBOARDING_ENGINE_URL` env var

## Implementation Notes

### Step 1: Onboarding engine — accept explicit tenant_id

In `engines/onboarding/models/tenant.py`, `TenantCreate` model:

```python
class TenantCreate(BaseModel):
    tenant_name: str
    description: Optional[str] = None
    tenant_id: Optional[str] = None   # NEW: accept explicit UUID from platform
    customer_id: Optional[str] = None  # NEW: platform user ID of creator
```

In `database/tenant_operations.py`, `create_tenant()`:
- If `data["tenant_id"]` is provided, use it; otherwise generate `uuid4()`
- If `data["customer_id"]` is provided, use it; otherwise use `tenant_id` as fallback

The onboarding engine's `POST /api/v1/tenants/` (find the router in `api/`) must pass
`tenant_id` and `customer_id` through to `create_tenant()`.

### Step 2: platform — call onboarding engine on tenant creation

In `platform/cspm-backend/user_auth/utils/tenant_utils.py`, modify `provision_first_tenant()`:

```python
import os
import requests as http_requests
import logging
import time

ONBOARDING_ENGINE_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding/api/v1")
logger = logging.getLogger(__name__)

def provision_first_tenant(user, company_name: str = "") -> Optional['Tenants']:
    """Create tenant in platform DB + onboarding engine DB with matching UUID."""
    from tenant_management.models import Tenants, TenantUsers
    from django.db import transaction

    if TenantUsers.objects.filter(user=user).exists():
        return None

    if not company_name:
        domain = user.email.split("@")[-1].split(".")[0].capitalize()
        company_name = f"{domain} (auto)"

    tenant_id = str(uuid.uuid4())

    with transaction.atomic():
        tenant = Tenants.objects.create(
            id=tenant_id,
            name=company_name,
            status="active",
            plan="trial",
            contact_email=user.email,
            created_by=user,
        )

        role = get_or_create_admin_role()
        TenantUsers.objects.create(
            id=str(uuid.uuid4()),
            tenant=tenant,
            user=user,
            role=role,
            is_active=True,
        )

        # Sync to onboarding engine with retry
        _sync_tenant_to_onboarding(tenant_id, company_name, str(user.id))
        # If _sync raises, transaction.atomic() rolls back the Django records

    logger.info(f"Provisioned tenant '{tenant.name}' (id={tenant_id}) for {user.email}")
    return tenant


def _sync_tenant_to_onboarding(
    tenant_id: str,
    tenant_name: str,
    customer_id: str,
    max_retries: int = 3
) -> None:
    """POST to onboarding engine to create matching tenant row. Raises on failure."""
    url = f"{ONBOARDING_ENGINE_URL}/tenants/"
    payload = {
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "customer_id": customer_id,
    }
    for attempt in range(max_retries):
        try:
            resp = http_requests.post(url, json=payload, timeout=10)
            if resp.status_code in (200, 201):
                return
            logger.warning(f"Onboarding sync attempt {attempt+1} got status {resp.status_code}")
        except http_requests.RequestException as e:
            logger.warning(f"Onboarding sync attempt {attempt+1} failed: {e}")
        if attempt < max_retries - 1:
            time.sleep(2 ** attempt)  # 1s, 2s backoff
    raise RuntimeError(f"Failed to sync tenant {tenant_id} to onboarding engine after {max_retries} attempts")
```

### Settings

Add to `platform/cspm-backend/config/settings.py`:
```python
ONBOARDING_ENGINE_URL = os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding/api/v1")
```

Add to `deployment/aws/eks/` platform manifest (or ConfigMap):
```yaml
- name: ONBOARDING_ENGINE_URL
  value: "http://engine-onboarding.threat-engine-engines.svc.cluster.local/api/v1"
```

### Verification query

After any tenant creation, verify:
```sql
-- Platform DB
SELECT id, name FROM tenants WHERE id = '{tenant_id}';
-- Onboarding DB
SELECT tenant_id, tenant_name FROM tenants WHERE tenant_id = '{tenant_id}';
-- Both must return the same UUID
```

## Reference Files

- `platform/cspm-backend/user_auth/utils/tenant_utils.py` — current provision_first_tenant
- `engines/onboarding/database/tenant_operations.py` — create_tenant (check if tenant_id is used)
- `engines/onboarding/models/tenant.py` — TenantCreate model

## Acceptance Criteria

- [ ] AC1: After `provision_first_tenant()`, the UUID in `platform.tenants.id` matches `onboarding.tenants.tenant_id`
- [ ] AC2: `customer_id` in onboarding DB equals `Users.id` of the tenant creator
- [ ] AC3: If onboarding engine is unreachable, Django tenant creation is rolled back (no orphaned platform tenant)
- [ ] AC4: `POST /api/v1/tenants/` in onboarding engine returns 200 when called with an explicit `tenant_id` that does not already exist
- [ ] AC5: `POST /api/v1/tenants/` in onboarding engine returns 409 when called with a `tenant_id` that already exists
- [ ] AC6: `ONBOARDING_ENGINE_URL` env var is documented in the platform K8s manifest

## Definition of Done

- [ ] Code follows Python standards (type hints, docstrings, 4-space indent)
- [ ] Transaction rollback tested (mock onboarding engine to return 500, verify no Django tenant created)
- [ ] Story accepted by SM before merge