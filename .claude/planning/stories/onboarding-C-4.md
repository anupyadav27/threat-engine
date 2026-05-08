---
story_id: onboarding-C-4
title: Agent bootstrap PKCE endpoint + heartbeat
status: ready
sprint: onboarding-revamp-C
depends_on: [onboarding-C-3]
blocks: [onboarding-D-5]
sme: Python/FastAPI/security engineer
estimate: 1.5 days
---

# Story: Agent bootstrap PKCE endpoint + heartbeat

## User Story
As an agent running on a customer's server, I want to exchange a PKCE `code_verifier`
for a long-lived session JWT, so that the raw bootstrap token is never transmitted over
the wire and the agent can authenticate with the onboarding engine for 30 days without
user interaction.

## Context
**BLOCK-04** from the security review:

The current `issue_agent_token` endpoint (lines 426–481 of `cloud_accounts.py`) stores
a SHA-256 hash of the raw token.  The raw token is returned in the response and also
embedded in the `install_command` field:
```
curl -sSL ... | bash -s -- --token {raw_token} ...
```
This puts the raw token in shell history, process listings, and log files.
MITRE ATT&CK: T1528 (Steal Application Access Token).

The fix implements a PKCE-like design:
1. UI generates `code_verifier = secrets.token_urlsafe(32)` on the frontend (never
   sent to the server in the issue step).
2. UI sends `code_challenge = SHA-256(code_verifier)` to `POST /agent-token`.
3. Server stores `code_challenge` (not a hash of the token — the challenge IS
   the hash).
4. Agent install command: `install.sh --registration-id {id} --verifier {code_verifier}`
5. Agent calls `POST /api/v1/agents/bootstrap` with `registration_id` + `code_verifier`.
   Server verifies `SHA-256(code_verifier) == stored code_challenge`.

Additionally, switch `issue_agent_token` from SHA-256 to `hashlib.pbkdf2_hmac` with
per-registration random salt, per BLOCK-04 minimum fix requirement.

The `agent_registrations` table already has `token_hash VARCHAR(512)` for this purpose
(migration applied in C-1).  A new `salt` column must be added if using PBKDF2, or the
existing column can store `salt:hash` as a combined value.

There is also no heartbeat mechanism — once an agent registers, the platform has no
liveness signal.  A `POST /api/v1/agents/{registration_id}/heartbeat` endpoint is
needed for the wizard polling (story D-5) and operator dashboards.

## Files to Create/Modify
- `engines/onboarding/api/cloud_accounts.py` — change `issue_agent_token()` token hashing; create new bootstrap router file or add to existing
- `engines/onboarding/api/agents.py` — new file: `POST /api/v1/agents/bootstrap` and `POST /api/v1/agents/{registration_id}/heartbeat` and `GET /api/v1/agents/{registration_id}/status`
- `engines/onboarding/main.py` — register new agents router
- `shared/database/migrations/` — small migration to add `salt` column to `agent_registrations` if using PBKDF2 salt stored separately

## Implementation Notes

### Change token hashing in `issue_agent_token`

Current (line 450):
```python
token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
```

Replace with PBKDF2 approach (minimum fix per security review):
```python
import os as _os
import hashlib as _hashlib

salt = _os.urandom(32).hex()   # 64-char hex string
token_hash = _hashlib.pbkdf2_hmac(
    'sha256',
    raw_token.encode(),
    salt.encode(),
    100_000
).hex()
# Store as "salt:hash" in the token_hash column (VARCHAR(512) is large enough)
token_hash_stored = f"{salt}:{token_hash}"
```

Update the INSERT to write `token_hash_stored`.

Update `install_command` to use PKCE pattern:
```python
# Do NOT embed the raw token in install_command
# Instead embed registration_id and the original code_verifier (passed by UI)
"install_command": (
    f"curl -sSL https://get.threat-engine.io/agent | bash -s -- "
    f"--registration-id {registration_id} "
    f"--verifier {raw_token}"   # raw_token is the code_verifier in PKCE mode
),
```

Note: In the PKCE design, `raw_token` IS the `code_verifier`.  The server stores
`SHA-256(code_verifier)` — so what was previously called `token_hash` becomes
`code_challenge_hash`.  Keep the DB column name `token_hash` for now (no column rename
needed — just semantics change).

### New file: `engines/onboarding/api/agents.py`

```python
"""
Agent bootstrap and lifecycle endpoints.
POST /api/v1/agents/bootstrap         — PKCE exchange: code_verifier → session JWT
POST /api/v1/agents/{id}/heartbeat    — agent liveness ping
GET  /api/v1/agents/{id}/status       — wizard polling endpoint
"""
```

#### `POST /api/v1/agents/bootstrap`

Request model:
```python
class AgentBootstrapRequest(BaseModel):
    registration_id: str = Field(..., description="UUID from agent_registrations")
    code_verifier:   str = Field(..., min_length=32, max_length=128,
                                 description="The verifier used to compute the code_challenge")
    agent_version:   Optional[str] = None
    agent_hostname:  Optional[str] = None
    agent_os:        Optional[str] = None
```

Logic:
1. Look up `agent_registrations` by `registration_id` where `status = 'issued'`.
2. Return 404 if not found or already activated/expired.
3. Check `expires_at > NOW()` — return 410 Gone if expired.
4. Verify: `SHA-256(code_verifier) == stored_token_hash` (or PBKDF2 if salt-based).
   Return 403 if mismatch.
5. On success:
   - Set `status = 'active'`, `activated_at = NOW()`, `expires_at = NOW() + 30 days`
   - Update agent metadata fields if provided
   - Update `cloud_accounts SET account_status = 'active', credential_validation_status = 'valid'`
   - Issue session JWT (see below)
   - Commit DB transaction
6. Return:
```json
{
  "session_jwt": "<30-day JWT>",
  "expires_in": 2592000,
  "account_id": "<str>",
  "tenant_id":  "<str>"
}
```

**Session JWT** — sign with `AGENT_JWT_SECRET` env var (separate from user session
secret).  Payload:
```json
{
  "sub": "<registration_id>",
  "account_id": "<account_id>",
  "tenant_id": "<tenant_id>",
  "type": "agent",
  "exp": <unix ts + 30 days>
}
```
Use `python-jose` or `PyJWT` (already in requirements if onboarding uses it; check
`engines/onboarding/requirements.txt`).

**This endpoint is NOT protected by `require_permission`** — it is the pre-auth
bootstrap.  It must NOT receive `X-Auth-Context`.  Exclude it from `AuthMiddleware`
by path pattern (same pattern as `/health/*`).

#### `POST /api/v1/agents/{registration_id}/heartbeat`

Requires agent JWT in `Authorization: Bearer <jwt>` header (NOT the user session cookie).
Add an `AgentJWTMiddleware` or a dedicated FastAPI Dependency `require_agent_jwt()` that
validates the JWT.

Logic:
1. Validate Bearer JWT → extract `registration_id` from `sub`.
2. Confirm path `registration_id` matches JWT `sub`.
3. `UPDATE agent_registrations SET last_heartbeat_at = NOW() WHERE registration_id = %s AND status = 'active'`
4. Return `{"status": "ok", "next_heartbeat_in": 300}`.

#### `GET /api/v1/agents/{registration_id}/status`

Protected by standard user `require_permission("cloud_accounts:read")`.
Used by the wizard to poll until `status = 'active'`.

Returns:
```json
{
  "registration_id": "...",
  "status": "issued|active|expired|revoked",
  "activated_at": "ISO-8601 or null",
  "last_heartbeat_at": "ISO-8601 or null",
  "account_id": "...",
  "expires_at": "ISO-8601"
}
```

### Register router in `main.py`

```python
from engine_onboarding.api.agents import router as agents_router
app.include_router(agents_router)
```

Exclude `/api/v1/agents/bootstrap` from `AuthMiddleware` (same mechanism as health
endpoints).

## Reference Files
- `/Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py` — lines 418–481 (current `issue_agent_token`)
- `/Users/apple/Desktop/threat-engine/engines/onboarding/main.py`
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/20260503_account_type_and_agent_registrations.sql`
- `/Users/apple/Desktop/threat-engine/.claude/documentation/SECURITY-REVIEW-AUTH-SPRINT.md` — BLOCK-04 and Agent Bootstrap Token Design section

## API Contract

### POST /api/v1/agents/bootstrap
```
Request:
  Content-Type: application/json
  Body: {
    "registration_id": "uuid",
    "code_verifier": "string (32-128 chars)",
    "agent_version": "1.0.0 (optional)",
    "agent_hostname": "srv-01 (optional)",
    "agent_os": "linux (optional)"
  }

Response 200:
  {
    "session_jwt": "eyJ...",
    "expires_in": 2592000,
    "account_id": "string",
    "tenant_id": "string"
  }

Response 403: { "detail": "Invalid code verifier" }
Response 404: { "detail": "Registration not found or already activated" }
Response 410: { "detail": "Bootstrap token has expired. Request a new agent token." }
```

### POST /api/v1/agents/{registration_id}/heartbeat
```
Request:
  Authorization: Bearer <session_jwt>

Response 200: { "status": "ok", "next_heartbeat_in": 300 }
Response 401: JWT invalid or expired
```

### GET /api/v1/agents/{registration_id}/status
```
Request:
  X-Auth-Context: <base64 auth context>

Response 200:
  {
    "registration_id": "uuid",
    "status": "issued|active|expired|revoked",
    "activated_at": "ISO-8601 or null",
    "last_heartbeat_at": "ISO-8601 or null",
    "account_id": "string",
    "expires_at": "ISO-8601"
  }
```

## Acceptance Criteria
- [ ] AC1: `POST /api/v1/agents/bootstrap` with correct `code_verifier` returns a JWT and updates `agent_registrations.status = 'active'`
- [ ] AC2: `POST /api/v1/agents/bootstrap` with wrong `code_verifier` returns 403
- [ ] AC3: `POST /api/v1/agents/bootstrap` after `expires_at` has passed returns 410
- [ ] AC4: `POST /api/v1/agents/bootstrap` second time on same `registration_id` returns 404 (already activated)
- [ ] AC5: `GET /api/v1/agents/{id}/status` returns `status: "active"` after successful bootstrap
- [ ] AC6: `POST /api/v1/agents/{id}/heartbeat` with valid agent JWT updates `last_heartbeat_at` within 1 second
- [ ] AC7: `issue_agent_token` no longer stores plain SHA-256 — uses PBKDF2 (100k iterations) with per-registration salt
- [ ] AC8: `install_command` in `issue_agent_token` response uses `--registration-id` and `--verifier` (no `--token`)
- [ ] AC9: `/api/v1/agents/bootstrap` path is excluded from `AuthMiddleware` (no 401 without X-Auth-Context)
- [ ] AC10: Unit tests: correct verifier → 200, wrong verifier → 403, expired → 410

## Definition of Done
- [ ] New `agents.py` router with all three endpoints
- [ ] `issue_agent_token` switched to PBKDF2
- [ ] Bootstrap endpoint excluded from AuthMiddleware
- [ ] Agent JWT validation dependency implemented
- [ ] Unit tests pass (mock DB calls)
- [ ] Docker image rebuilt and deployed
- [ ] Story accepted by SM before merge
