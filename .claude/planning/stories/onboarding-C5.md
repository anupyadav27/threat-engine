---
id: onboarding-C5
title: "account_type validation against tenant_type"
sprint: C
points: 0.5
depends_on: [onboarding-C1]
blocks: []
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

With the addition of `account_type` to `cloud_accounts` (from onboarding-C1) and `tenant_type` to Django tenants (from auth-A1), the system can now enforce that account types are consistent with their parent tenant type. For example, a `vulnerability`-type account should only be created under a tenant with `tenant_type='vulnerability'`, and `secops`-type accounts only under `tenant_type='secops'`. Without this validation, a user could create a `cloud_csp` AWS account under a vulnerability-only tenant, which would produce confusing scan results. This story adds a validation step to the cloud account creation endpoint in `engines/onboarding/api/cloud_accounts.py` — before writing to DB, call Django to get the tenant's `tenant_type` and verify it is compatible with the requested `account_type`.

## Acceptance Criteria

- [ ] AC1: Attempting to create a `cloud_csp` account under a tenant with `tenant_type='vulnerability'` returns HTTP 422 with `{"detail": "account_type 'cloud_csp' is not permitted for tenant_type 'vulnerability'"}`.
- [ ] AC2: Attempting to create a `vulnerability` account under a tenant with `tenant_type='cloud'` returns HTTP 422 with appropriate message.
- [ ] AC3: The compatibility matrix is: `cloud_csp` → `'cloud'` tenant only; `vulnerability` → `'vulnerability'` tenant only; `secops` → `'secops'` tenant only.
- [ ] AC4: Validation is applied in the account creation endpoint BEFORE the DB write (fail fast).
- [ ] AC5: The tenant_type is fetched from the Django API using the `tenant_id` from `auth.tenant_id` (X-Auth-Context) — never from the request body.
- [ ] AC6: If the Django API is unreachable (timeout), the validation returns HTTP 503 with `{"detail": "Tenant service unavailable — retry"}` (do not silently skip validation).
- [ ] AC7: A utility function `validate_account_type_for_tenant(account_type: str, tenant_type: str) -> bool` is in a separate module (not inline in the endpoint).
- [ ] AC8: Unit tests: valid combinations pass; all invalid combinations fail with 422; Django timeout returns 503.

## Key Files

- `engines/onboarding/api/cloud_accounts.py` — Add validation call in account creation endpoint
- `engines/onboarding/validators/account_type.py` (create) — `validate_account_type_for_tenant()` function
- `engines/onboarding/utils/django_client.py` (create or extend) — `get_tenant_type(tenant_id: str) -> str` helper

## Technical Notes

**Compatibility matrix as a constant:**
```python
# validators/account_type.py
ACCOUNT_TYPE_TENANT_TYPE_MAP: dict[str, str] = {
    "cloud_csp":     "cloud",
    "vulnerability": "vulnerability",
    "secops":        "secops",
}

def validate_account_type_for_tenant(account_type: str, tenant_type: str) -> bool:
    """Returns True if the account_type is compatible with the tenant_type."""
    allowed_tenant_type = ACCOUNT_TYPE_TENANT_TYPE_MAP.get(account_type)
    if allowed_tenant_type is None:
        raise ValueError(f"Unknown account_type: {account_type}")
    return tenant_type == allowed_tenant_type
```

**Django API call to get tenant_type:**
```python
# utils/django_client.py
import os, requests

DJANGO_API_URL = os.environ.get("DJANGO_API_URL", "http://cspm-backend.threat-engine-engines.svc.cluster.local:8000")
INTERNAL_SECRET = os.environ["X_INTERNAL_SECRET"]

def get_tenant_type(tenant_id: str) -> str:
    """Fetch tenant_type from Django for the given tenant_id."""
    resp = requests.get(
        f"{DJANGO_API_URL}/internal/tenants/{tenant_id}/type",
        headers={"X-Internal-Secret": INTERNAL_SECRET},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()["tenant_type"]
```

**Integration in account creation endpoint:**
```python
@router.post("/cloud-accounts")
async def create_cloud_account(
    body: CloudAccountCreate,
    auth: AuthContext = Depends(require_permission("cloud_accounts:write")),
):
    tenant_id = auth.tenant_id  # from X-Auth-Context, never from body
    try:
        tenant_type = get_tenant_type(tenant_id)
    except requests.exceptions.Timeout:
        raise HTTPException(503, "Tenant service unavailable — retry")

    if not validate_account_type_for_tenant(body.account_type, tenant_type):
        raise HTTPException(
            422,
            f"account_type '{body.account_type}' is not permitted for tenant_type '{tenant_type}'"
        )
    # proceed to DB write
```

**Django internal endpoint for tenant_type** (must be added to Django in this story or verified it already exists):
```python
# Django view: /internal/tenants/{tenant_id}/type
# Returns: {"tenant_type": "cloud" | "vulnerability" | "secops"}
# Auth: X-Internal-Secret header
```

**Verify Django internal endpoint:**
```bash
grep -rn "internal.*tenant\|tenant.*type" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py" | grep -i "url\|view\|route"
```

## Security Checklist

- [ ] `tenant_id` from `auth.tenant_id` (X-Auth-Context), never from request body
- [ ] Django internal call uses `X-Internal-Secret`, not a user-facing cookie
- [ ] `require_permission("cloud_accounts:write")` already present on endpoint (added in C3)
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `validate_account_type_for_tenant()` in separate module with unit tests
- [ ] Django internal endpoint `/internal/tenants/{id}/type` returns correct `tenant_type`
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s
