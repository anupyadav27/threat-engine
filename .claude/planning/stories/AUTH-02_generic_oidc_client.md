---
story_id: AUTH-02
title: Generic OIDC login + callback (authlib)
status: ready
sprint: auth-redesign-1
depends_on: [AUTH-01]
blocks: [AUTH-03, AUTH-08]
sme: Django/Python backend engineer
estimate: 2 days
---

# Story: Generic OIDC Login + Callback

## Context

The platform currently has only Google OAuth (hardcoded to Google endpoints) and Okta SAML.
No OIDC IDP other than Google can be used. This story implements a generic OIDC client
using `authlib` that reads per-tenant IDP config from `TenantIDPConfig` (created in AUTH-01)
and handles any OIDC 1.0-compliant provider (Okta, Entra ID, Cognito, Auth0, Keycloak, etc.).

This is the core auth flow unblocking all non-Google SSO use cases.

## Files to Create/Modify

- `platform/cspm-backend/user_auth/views/oidc_auth.py` — NEW: OIDC login + callback views
- `platform/cspm-backend/user_auth/urls.py` — add OIDC routes
- `platform/cspm-backend/requirements.txt` — add `authlib>=1.3.0`
- `platform/cspm-backend/config/settings.py` — add OIDC session config

## Implementation Notes

### Install authlib

Add to `requirements.txt`:
```
authlib>=1.3.0
requests>=2.31.0   # already present, confirm version
```

### OIDC Login View

`GET /api/auth/oidc/login/?tenant={tenant_id}&redirect_after=/dashboard`

Flow:
1. Load `TenantIDPConfig` for `tenant_id` where `idp_type='oidc'` and `is_active=True`
2. Fetch OIDC discovery document from `{issuer}/.well-known/openid-configuration` (cache for 5 min)
3. Generate `state` = HMAC-SHA256(json({"tenant_id": ..., "nonce": ..., "redirect_after": ...}), SECRET_KEY)
4. Store `state` in Django session (`request.session['oidc_state'] = state`)
5. If `pkce=True` in config: generate `code_verifier` (43-128 chars URL-safe), store in session, compute `code_challenge = base64url(sha256(code_verifier))`
6. Redirect to IDP authorization URL with params: `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `nonce`, optionally `code_challenge` + `code_challenge_method=S256`

Redirect URI: `https://{platform_domain}/api/auth/oidc/callback/` (single callback URL for all tenants — tenant_id is recovered from `state`)

### OIDC Callback View

`GET /api/auth/oidc/callback/?code=...&state=...`

Flow:
1. Verify `state` matches session `oidc_state` — if mismatch, return 400 (CSRF protection)
2. Decode state to extract `tenant_id` and `redirect_after`
3. Load `TenantIDPConfig` for `tenant_id`
4. Exchange `code` for tokens via `POST {token_endpoint}` with `client_id`, `client_secret` (resolved from Secrets Manager via `config.client_secret_ref`), `code`, `redirect_uri`, `grant_type=authorization_code`, plus `code_verifier` if PKCE
5. Validate ID token: use `authlib.integrations.requests_client.OAuth2Session` with JWKS validation
6. Extract `email` from ID token claims (map via `config.claims_mapping.email`)
7. Upsert `Users` record: `email`, `first_name`, `last_name`, `sso_provider='oidc'`, `sso_id={sub claim}`
8. If new user: call `provision_first_tenant(user)` — this now also calls onboarding engine (AUTH-06)
9. Create `UserSessions` with `login_method=f"oidc:{config.idp_name}"`
10. Set httponly cookies (reuse `set_auth_cookies` from `user_auth.utils.cookie_utils`)
11. Redirect to `redirect_after` or `/dashboard`

### Secrets Manager Helper

Reuse pattern from `engines/onboarding/storage/secrets_manager_storage.py`.
Create `platform/cspm-backend/user_auth/utils/secrets_utils.py`:

```python
import boto3
import json
from functools import lru_cache

def get_idp_client_secret(secret_ref: str) -> str:
    """Fetch OIDC/OAuth client secret from AWS Secrets Manager."""
    client = boto3.client('secretsmanager', region_name=settings.AWS_REGION)
    response = client.get_secret_value(SecretId=secret_ref)
    secret = json.loads(response['SecretString'])
    return secret['client_secret']
```

### URL Registration

In `user_auth/urls.py`, add:
```python
path("oidc/login/", OIDCLoginView.as_view(), name="oidc_login"),
path("oidc/callback/", OIDCCallbackView.as_view(), name="oidc_callback"),
```

### Settings

Add to `config/settings.py`:
```python
OIDC_DISCOVERY_CACHE_TTL = 300  # seconds
OIDC_CALLBACK_URL = os.getenv("OIDC_CALLBACK_URL", "http://localhost:8000/api/auth/oidc/callback/")
```

## Reference Files

- `platform/cspm-backend/user_auth/views/google_auth.py` — existing OAuth pattern to replace
- `platform/cspm-backend/user_auth/utils/auth_utils.py` — `generate_token`, `hash_token`
- `platform/cspm-backend/user_auth/utils/cookie_utils.py` — `set_auth_cookies`
- `platform/cspm-backend/user_auth/utils/tenant_utils.py` — `provision_first_tenant`
- `engines/onboarding/storage/secrets_manager_storage.py` — Secrets Manager pattern

## Acceptance Criteria

- [ ] AC1: `GET /api/auth/oidc/login/?tenant={valid_tenant_id}` returns 302 redirect to IDP authorization URL containing `state`, `nonce`, `client_id`, `scope=openid email profile`
- [ ] AC2: `GET /api/auth/oidc/login/?tenant={invalid_tenant_id}` returns 404 JSON
- [ ] AC3: Callback with mismatched `state` returns 400 (CSRF protection verified)
- [ ] AC4: Callback with valid code creates `UserSessions` row with `login_method` containing `'oidc:'` prefix
- [ ] AC5: Callback sets `access_token` and `refresh_token` httponly cookies
- [ ] AC6: New user triggers `provision_first_tenant()` exactly once
- [ ] AC7: PKCE `code_verifier`/`code_challenge` are used when `config.pkce=True`
- [ ] AC8: ID token is validated via JWKS (not just userinfo endpoint)
- [ ] AC9: `client_secret` is read from Secrets Manager, never from DB or env var directly

## Definition of Done

- [ ] Code follows Python standards (type hints, docstrings, 4-space indent)
- [ ] Unit tests with mocked IDP responses (mock `requests.post` and JWKS fetch)
- [ ] No regression: existing Google OAuth flow still works
- [ ] `authlib` added to `requirements.txt`
- [ ] Story accepted by SM before merge
