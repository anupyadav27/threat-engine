---
id: onboarding-C4
title: "PKCE agent bootstrap + heartbeat endpoint"
sprint: C
points: 1.5
depends_on: [onboarding-C1, onboarding-C3]
blocks: [onboarding-D9]
security_blocks: [BLOCK-04]
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-09
---

## Context

BLOCK-04: The onboarding engine has a PKCE agent token generation endpoint but it is not properly gated — the PKCE verifier is not being validated before issuing a token. Additionally, the VUL agent heartbeat endpoint does not exist, which means there is no way for an installed agent to report its status back to the platform. This story: (1) hardens the `POST /api/v1/cloud-accounts/{id}/agent-token` endpoint to properly validate the PKCE challenge, (2) creates `GET /api/v1/agent/heartbeat` for agent status polling, and (3) writes the generated agent token hash to `agent_registrations` table (created in C1). The raw token is stored in AWS SM, the SHA-256 hash is stored in DB. The architecture decision for MVP is static `API_KEYS` injection into VUL engine (not full JWT verification). The `run_now` flag in the heartbeat response enables the "trigger scan from UI" flow used in onboarding-C7.

## Acceptance Criteria

- [ ] AC1 (BLOCK-04): `POST /api/v1/cloud-accounts/{id}/agent-token` validates the PKCE code verifier (`X-PKCE-Verifier` header) before issuing a token. Returns 400 if verifier is missing or invalid.
- [ ] AC2: The generated raw agent token is a UUID4 string, stored in AWS SM at `threat-engine/account/{account_id}`, and NEVER written to the PostgreSQL DB.
- [ ] AC3: `agent_registrations` table row is created with `agent_token_hash = sha256(raw_token).hexdigest()`, `status='pending'`, `tenant_id` from auth context.
- [ ] AC4: Response `POST /api/v1/cloud-accounts/{id}/agent-token` returns:
  ```json
  {
    "install_command": "curl -sSL https://agents.onam.cloud/install.sh | bash -s -- --tenant <tid> --token <raw_token>",
    "token_expires_in": 1800,
    "account_id": "<id>"
  }
  ```
- [ ] AC5: `GET /api/v1/agent/heartbeat` endpoint exists, authenticates agent using `Authorization: Bearer <raw_token>` header by looking up `sha256(token)` in `agent_registrations.agent_token_hash`.
- [ ] AC6: On successful heartbeat: `agent_registrations.last_heartbeat = NOW()`, `status = 'connected'`, `connected_at` set on first connection.
- [ ] AC7: Heartbeat response returns `{"status": "ok", "run_now": false, "updated_at": "<iso8601>"}`. `run_now` is set to `true` if the account has a pending ad-hoc scan trigger (see onboarding-C7 for the trigger mechanism).
- [ ] AC8: Heartbeat endpoint does NOT require the platform cookie auth — it uses Bearer token auth from the `agent_registrations` table lookup only.
- [ ] AC9: A new router file `engines/onboarding/routers/agent.py` contains these endpoints (do not add to `cloud_accounts.py`).
- [ ] AC10: Unit tests: PKCE verifier missing → 400; valid verifier → 200 with install_command; heartbeat with invalid token → 401; heartbeat with valid token → 200 and DB updated.

## Key Files

- `engines/onboarding/routers/agent.py` — Create: agent-token and heartbeat endpoints
- `engines/onboarding/main.py` — Register the new agent router
- `engines/onboarding/database/cloud_accounts_operations.py` — Add `create_agent_registration()` and `update_agent_heartbeat()` functions
- `engines/onboarding/storage/secrets_manager_storage.py` — Verify `store_agent_token()` method exists or add it

## Technical Notes

**SHA-256 token hash:**
```python
import hashlib
from uuid import uuid4

def generate_agent_token() -> tuple[str, str]:
    """Returns (raw_token, token_hash)"""
    raw_token = str(uuid4())
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash
```

**PKCE validation:**
```python
import hashlib, base64

def validate_pkce_verifier(code_challenge: str, code_verifier: str) -> bool:
    """Validate PKCE S256 challenge. code_challenge stored at /cloud-accounts/{id} auth flow init."""
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return computed == code_challenge
```

**SM storage path:**
```python
SM_PATH = f"threat-engine/account/{account_id}"
# Store: {"agent_token": raw_token, "account_type": "vulnerability"}
```

**SM is a string — json.loads IS correct here:**
```python
import json
response = sm_client.get_secret_value(SecretId=SM_PATH)
data = json.loads(response["SecretString"])  # correct — SM returns str
```

**Agent heartbeat auth (not cookie-based):**
```python
async def agent_auth(authorization: str = Header(None)) -> str:
    """Extract and validate Bearer token from agent heartbeat."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing agent token")
    raw_token = authorization.removeprefix("Bearer ")
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    reg = await db.fetch_agent_registration_by_hash(token_hash)
    if not reg:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return reg["account_id"]
```

**run_now flag:** Store a `run_now_requested BOOLEAN DEFAULT FALSE` flag on `agent_registrations` (or a separate field in cloud_accounts). When onboarding-C7 ad-hoc scan is triggered for an agent account, set this flag. Heartbeat response returns `"run_now": true` and clears the flag.

**AWS SM KMS key env var:** `AWS_SM_KMS_KEY_ID` — must be present in the onboarding engine's environment.

**Verify SM path convention:**
```bash
grep -n "threat-engine/account" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/storage/secrets_manager_storage.py
```

## Security Checklist

- [ ] Raw agent token never written to PostgreSQL — only SHA-256 hash stored in `agent_registrations`
- [ ] PKCE S256 verifier validated before token issuance
- [ ] SM path uses `threat-engine/account/{account_id}` convention
- [ ] SM write uses `AWS_SM_KMS_KEY_ID` (platform KMS key, not default AWS-managed key)
- [ ] Heartbeat endpoint uses Bearer token auth — no cookie bypass
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] Raw token in SM at `threat-engine/account/{account_id}` confirmed via SM console
- [ ] `agent_registrations` row created with correct hash (verify: `sha256(raw_token) == stored_hash`)
- [ ] Heartbeat endpoint updates `last_heartbeat` within 5 seconds
- [ ] Unit tests: 6 test cases (AC1, AC2/AC3, AC4, AC5, AC6, AC10)
- [ ] bmad-security-reviewer: no BLOCKERs (BLOCK-04 resolved)
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s