---
id: onboarding-C3
title: "Auth middleware (BUG-04/05) — add require_permission() to 3 endpoints"
sprint: C
points: 1
depends_on: []
blocks: [onboarding-C4, onboarding-C6]
security_blocks: [BLOCK-05, BLOCK-06]
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: IAM-09
---

## Context

BUG-05 from the architecture audit: three endpoints in `engines/onboarding/api/cloud_accounts.py` are missing `Depends(require_permission())` guards: (1) the credential validation endpoint, (2) the log-sources PUT endpoint, (3) the log-sources GET endpoint. BLOCK-05 requires that the onboarding engine's auth middleware is correctly wired so `X-Auth-Context` header is parsed by the gateway and forwarded to the engine. BLOCK-06 requires that PATCH endpoints on cloud_accounts have an explicit allow-list of patchable fields — preventing mass assignment attacks where a caller submits fields like `tenant_id` or `customer_id` in the request body. The `require_permission()` dependency is already implemented in `shared/common/` for other engines — import and use the same pattern. Do NOT add any auth bypass headers.

## Acceptance Criteria

- [ ] AC1 (BUG-05): The credential validation endpoint in `cloud_accounts.py` has `Depends(require_permission("cloud_accounts:write"))` in its function signature.
- [ ] AC2 (BUG-05): The log-sources PUT endpoint in `cloud_accounts.py` has `Depends(require_permission("cloud_accounts:write"))`.
- [ ] AC3 (BUG-05): The log-sources GET endpoint in `cloud_accounts.py` has `Depends(require_permission("cloud_accounts:read"))`.
- [ ] AC4 (BLOCK-05): `GET /api/v1/health/live` returns 200 without auth cookie (health endpoints are exempt from auth).
- [ ] AC5 (BLOCK-05): Any non-health endpoint called without a valid `X-Auth-Context` header returns HTTP 401 or 403.
- [ ] AC6 (BLOCK-06): PATCH endpoint on `cloud_accounts` uses an explicit Pydantic schema (e.g., `CloudAccountPatch`) that only allows a defined allow-list of fields: `account_name`, `description`, `schedule_id`, `validation_status`. Fields `tenant_id`, `customer_id`, `account_id`, `credential_ref` must NOT be patchable via this endpoint.
- [ ] AC7 (BLOCK-06): If a PATCH request body includes `tenant_id` or `customer_id`, the engine ignores those fields (Pydantic `extra='ignore'` or explicit exclusion).
- [ ] AC8: `require_permission()` is imported from the shared common library — not reimplemented inline.
- [ ] AC9: Unit tests: unauthenticated call → 401/403; authorized call → 200; PATCH with `tenant_id` in body → field is silently ignored; wrong permission → 403.

## Key Files

- `engines/onboarding/api/cloud_accounts.py` — Add `Depends(require_permission(...))` to 3 endpoints; add PATCH allow-list schema
- `engines/onboarding/main.py` — Verify auth middleware is registered as FastAPI middleware (not just on individual routes)
- `engines/onboarding/models/` or `engines/onboarding/api/schemas.py` — Add `CloudAccountPatch` Pydantic model

## Technical Notes

**Locate the 3 endpoints missing auth:**
```bash
grep -n "def.*credential\|def.*log.source\|def.*validate" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py
```

**require_permission import pattern (match other engines):**
```bash
grep -rn "require_permission\|from.*auth.*import" \
  /Users/apple/Desktop/threat-engine/engines/check/ --include="*.py" | head -5
# Use same import path as check engine
```

**Apply require_permission:**
```python
from shared.auth import require_permission  # adjust import to match project pattern
# OR
from engine_common.auth import require_permission

@router.post("/cloud-accounts/{account_id}/validate-credentials")
async def validate_credentials(
    account_id: UUID,
    auth: AuthContext = Depends(require_permission("cloud_accounts:write")),
):
    ...
```

**PATCH allow-list schema (BLOCK-06):**
```python
from pydantic import BaseModel
from typing import Optional

class CloudAccountPatch(BaseModel):
    account_name: Optional[str] = None
    description: Optional[str] = None
    schedule_id: Optional[str] = None

    class Config:
        extra = 'ignore'  # silently drops tenant_id, customer_id, etc.

@router.patch("/cloud-accounts/{account_id}")
async def patch_cloud_account(
    account_id: UUID,
    body: CloudAccountPatch,
    auth: AuthContext = Depends(require_permission("cloud_accounts:write")),
):
    # Only update fields present in CloudAccountPatch
    ...
```

**tenant_id extraction in this engine — always from auth context:**
```python
tenant_id = auth.tenant_id  # from X-Auth-Context, never from request body
```

**Verify all endpoints have require_permission:**
```bash
grep -n "def " /Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py | \
  grep -v "require_permission\|health"
# Any endpoint not in health.py that lacks require_permission is a gap
```

**Auth middleware check in main.py:**
```bash
grep -n "middleware\|AuthMiddleware\|X-Auth-Context" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/main.py
# Should show middleware registration
```

## Security Checklist

- [ ] `require_permission()` on ALL three identified endpoints (not just one)
- [ ] PATCH allow-list via Pydantic `extra='ignore'` — no mass assignment possible
- [ ] `tenant_id` extracted from `auth.tenant_id` (X-Auth-Context), never from request body
- [ ] No `DEV_BYPASS_AUTH` or similar bypass — ever
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge (SECURITY CRITICAL)

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -n "Depends(require_permission" engines/onboarding/api/cloud_accounts.py` shows at least 3 additional entries vs before this story
- [ ] PATCH schema has `extra = 'ignore'` or equivalent
- [ ] bmad-security-reviewer: no BLOCKERs (BLOCK-05 and BLOCK-06 resolved, BUG-05 fixed)
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: Argo pipeline callback still authenticates correctly (verify with a known scan_run_id)
