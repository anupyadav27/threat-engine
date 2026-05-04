---
story_id: onboarding-C-3
title: Auth middleware on onboarding engine + PATCH allow-list (BLOCK-05, BLOCK-06)
status: ready
sprint: onboarding-revamp-C
depends_on: []
blocks: [onboarding-C-4]
sme: Python/FastAPI/RBAC engineer
estimate: 1 day
---

# Story: Auth middleware on onboarding engine + PATCH allow-list

## User Story
As a security engineer, I want every onboarding engine endpoint to require a valid
`X-Auth-Context` header and enforce RBAC permissions, so that unauthenticated callers
cannot read or write cloud account credentials.

## Context
BLOCK-05 and BLOCK-06 from the security review
(`/Users/apple/Desktop/threat-engine/.claude/documentation/SECURITY-REVIEW-AUTH-SPRINT.md`):

**BLOCK-05** — The onboarding engine has no auth middleware.  `main.py` only adds
`CORSMiddleware` (line 70–76).  All 18 other production engines have an `AuthMiddleware`
that reads the `X-Auth-Context` header (set by the API gateway from the validated
`access_token` cookie) and builds an `AuthContext` object.  The onboarding engine
bypasses this entirely — any caller who can reach the pod can read credentials
and issue agent tokens.  MITRE ATT&CK: T1190.

**BLOCK-06** — `update_account()` at line 201 of `cloud_accounts.py` accepts
`updates: dict` directly.  Any field in `cloud_accounts` can be overwritten including
`credential_ref` and `tenant_id`.  There is also no check that the account being
updated belongs to the requesting user's tenant.  MITRE ATT&CK: T1190.

The pattern to follow is already live in 18 other engines.  Look at
`engines/discoveries/main.py` or `engines/check/main.py` for the `AuthMiddleware`
import and registration pattern.

## Files to Create/Modify
- `engines/onboarding/main.py` — add `AuthMiddleware` registration
- `engines/onboarding/api/cloud_accounts.py` — replace `updates: dict`, add permission guards, add tenant ownership checks

## Implementation Notes

### Adding AuthMiddleware to `main.py`

The shared auth middleware lives in `shared/auth/` and is available as
`engine_common.auth` or imported from `shared/auth/core/middleware.py` depending on
the engine package layout.

Check how another engine imports it, e.g.:
```bash
grep -r "AuthMiddleware" /Users/apple/Desktop/threat-engine/engines/discoveries/
```

Add after the CORSMiddleware block in `main.py`:
```python
from engine_common.auth.middleware import AuthMiddleware  # adjust path to match other engines
app.add_middleware(AuthMiddleware)
```

The `AuthMiddleware`:
- Reads `X-Auth-Context` header (Base64-encoded JSON set by the gateway)
- Builds `AuthContext` dataclass and attaches to `request.state.auth_context`
- Returns 401 if header is absent on non-health-check routes
- Does NOT verify tokens itself — that is the gateway's job

**Exclude from auth check** (same pattern as other engines):
- `GET /api/v1/health/live`
- `GET /api/v1/health/ready`
- `GET /` (root)
- `GET /docs` (Swagger UI)

### `require_permission()` on endpoints in `cloud_accounts.py`

Import the dependency:
```python
from engine_common.auth.dependencies import require_permission, get_auth_context
```

Apply to each endpoint:
```python
# Read endpoints
@router.get("")
async def list_accounts(..., _: None = Depends(require_permission("cloud_accounts:read"))):

@router.get("/{account_id}")
async def get_account(account_id: str, _: None = Depends(require_permission("cloud_accounts:read"))):

@router.get("/{account_id}/status")
async def get_account_status(account_id: str, _: None = Depends(require_permission("cloud_accounts:read"))):

# Write endpoints
@router.post("")
async def create_account(body: CloudAccountCreate, _: None = Depends(require_permission("cloud_accounts:write"))):

@router.patch("/{account_id}")
async def update_account(account_id: str, body: CloudAccountUpdate,
                         auth: AuthContext = Depends(get_auth_context),
                         _: None = Depends(require_permission("cloud_accounts:write"))):

@router.delete("/{account_id}")
async def delete_account(account_id: str, _: None = Depends(require_permission("cloud_accounts:write"))):

@router.post("/{account_id}/credentials")
async def store_credentials(account_id: str, body: CredentialStore,
                            _: None = Depends(require_permission("cloud_accounts:write"))):

@router.post("/{account_id}/agent-token")
async def issue_agent_token(account_id: str, body: AgentTokenRequest,
                            _: None = Depends(require_permission("cloud_accounts:write"))):
```

### Replace `updates: dict` with `CloudAccountUpdate` Pydantic model

The current signature on line 201:
```python
async def update_account(account_id: str, updates: dict):
```

Replace with a new Pydantic model (add near the top of cloud_accounts.py with the
other models):
```python
class CloudAccountUpdate(BaseModel):
    """Allow-listed fields for PATCH /cloud-accounts/{id}.

    Explicitly excluded (must NOT be patchable via API):
      - credential_ref (managed by /credentials endpoint only)
      - tenant_id (immutable once set)
      - customer_id (immutable)
      - account_id (primary key)
    """
    account_name:     Optional[str]  = Field(None, min_length=1, max_length=255)
    account_status:   Optional[str]  = Field(None, pattern="^(active|inactive|pending)$")
    log_sources:      Optional[Dict[str, Any]] = None
    account_type:     Optional[str]  = Field(None,
        description="Must match the parent tenant's tenant_type valid set")
    auth_config:      Optional[Dict[str, Any]] = None
```

Update the endpoint signature:
```python
async def update_account(account_id: str, body: CloudAccountUpdate,
                         auth: AuthContext = Depends(get_auth_context),
                         _: None = Depends(require_permission("cloud_accounts:write"))):
```

### Tenant ownership check in `update_account` and `delete_account`

Before performing any write, fetch the account and verify ownership:
```python
account = get_cloud_account(account_id)
if not account:
    raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

# Tenant ownership check — prevent cross-tenant writes
if account["tenant_id"] != auth.engine_tenant_id:
    raise HTTPException(status_code=403, detail="Forbidden")
```

Apply the same check in `delete_account`.

For `store_credentials` and `issue_agent_token`, add the same ownership check using
`body.tenant_id` vs `auth.engine_tenant_id`.

## Reference Files
- `/Users/apple/Desktop/threat-engine/engines/onboarding/main.py`
- `/Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py`
- `/Users/apple/Desktop/threat-engine/.claude/documentation/SECURITY-REVIEW-AUTH-SPRINT.md` — BLOCK-05, BLOCK-06
- `/Users/apple/Desktop/threat-engine/.claude/documentation/RBAC.md` — permission matrix
- Another engine's `main.py` for `AuthMiddleware` import pattern

## API Contract

No new endpoints — changes are security additions to existing endpoints.

### PATCH /api/v1/cloud-accounts/{account_id}

Before (broken):
```
Body: any dict — arbitrary fields including credential_ref, tenant_id
```

After (fixed):
```json
{
  "account_name": "string (optional)",
  "account_status": "active|inactive|pending (optional)",
  "log_sources": {} ,
  "account_type": "string (optional)",
  "auth_config": {}
}
```
Returns 400 if any non-allow-listed field is detected (Pydantic validation).
Returns 403 if `account.tenant_id != auth_context.engine_tenant_id`.

## Acceptance Criteria
- [ ] AC1: `GET /api/v1/cloud-accounts` without `X-Auth-Context` header returns 401
- [ ] AC2: `GET /api/v1/health/live` without `X-Auth-Context` returns 200 (health excluded from auth)
- [ ] AC3: `PATCH /api/v1/cloud-accounts/{id}` with body `{"credential_ref": "evil/path"}` returns 422 (Pydantic validation rejects it)
- [ ] AC4: `PATCH /api/v1/cloud-accounts/{id}` where account belongs to a different tenant returns 403
- [ ] AC5: `PATCH /api/v1/cloud-accounts/{id}` with `{"account_name": "new-name"}` from correct tenant returns 200 with updated name
- [ ] AC6: `POST /api/v1/cloud-accounts/{id}/agent-token` without `cloud_accounts:write` permission in AuthContext returns 403
- [ ] AC7: Unit test for ownership check: mock an account with `tenant_id="T1"`, set auth context `engine_tenant_id="T2"`, assert 403
- [ ] AC8: RBAC matrix: viewer role (9 permissions, no `cloud_accounts:write`) → all write endpoints return 403

## Definition of Done
- [ ] `AuthMiddleware` registered in `main.py`
- [ ] `CloudAccountUpdate` Pydantic model with explicit allow-list
- [ ] `require_permission()` on all read and write endpoints
- [ ] Tenant ownership check in update and delete endpoints
- [ ] Unit tests cover: no auth header, wrong tenant, allow-list validation
- [ ] Swagger docs show updated request schema for PATCH endpoint
- [ ] Docker image rebuilt and deployed to EKS
- [ ] `kubectl logs` shows auth context being parsed on first request
- [ ] Story accepted by SM before merge
