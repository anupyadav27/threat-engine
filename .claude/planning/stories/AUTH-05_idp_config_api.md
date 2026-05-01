---
story_id: AUTH-05
title: TenantIDPConfig REST API (CRUD)
status: ready
sprint: auth-redesign-1
depends_on: [AUTH-01]
blocks: [AUTH-08]
sme: Django/Python backend engineer
estimate: 1 day
---

# Story: TenantIDPConfig REST API

## Context

Tenant admins need a way to configure their IDP via the UI. This story exposes the
`TenantIDPConfig` model (AUTH-01) as a REST API so:
1. Tenant admins can add, update, and delete their IDP configurations
2. The onboarding wizard (AUTH-10, sprint 2) can drive IDP setup
3. The OIDC (AUTH-02) and SAML (AUTH-04) views can look up configs at login time

## Files to Create/Modify

- `platform/cspm-backend/tenant_management/views.py` — add IDP config views
- `platform/cspm-backend/tenant_management/urls.py` — add IDP config routes
- `platform/cspm-backend/tenant_management/serializers.py` — `TenantIDPConfigSerializer` (already started in AUTH-01)

## Implementation Notes

### Routes

Add to `tenant_management/urls.py`:

```python
path("idp/", TenantIDPConfigListCreateView.as_view(), name="idp_config_list_create"),
path("idp/<str:pk>/", TenantIDPConfigDetailView.as_view(), name="idp_config_detail"),
path("idp/<str:pk>/activate/", TenantIDPConfigActivateView.as_view(), name="idp_config_activate"),
```

Full path after gateway: `GET /api/v1/tenants/idp/` and `GET /api/v1/tenants/idp/{id}/`

### Authentication

Reuse the `_current_user()` pattern from `user_auth/views/invite.py`. Wrap into a
shared decorator or util in `user_auth/utils/auth_utils.py`:

```python
def require_auth(request) -> Optional[Users]:
    """Return authenticated user from access_token cookie or None."""
```

### TenantIDPConfigListCreateView

`GET /api/v1/tenants/idp/` — list IDP configs for the authenticated user's tenant
`POST /api/v1/tenants/idp/` — create new IDP config

**GET**: Return all `TenantIDPConfig` rows where `tenant_id` is any tenant the user belongs to.
Exclude `config.client_secret_ref` value (replace with `"[stored]"` sentinel) from response.

**POST** body:
```json
{
  "tenant_id": "uuid",
  "idp_type": "oidc",
  "idp_name": "Acme Okta",
  "config": {
    "issuer": "https://acme.okta.com/oauth2/default",
    "client_id": "...",
    "client_secret": "...",
    "scopes": ["openid", "email", "profile"],
    "pkce": true
  },
  "allowed_domains": ["acme.com"]
}
```

On POST:
1. Validate user belongs to `tenant_id` with `is_active=True`
2. Extract `client_secret` from `config`, store in Secrets Manager at
   `platform/idp/{tenant_id}/{idp_type}`, replace with `client_secret_ref` in `config`
3. If `idp_type='saml'` and no existing SP cert: call `generate_sp_keypair(tenant_id)` from `saml_utils`
4. Save `TenantIDPConfig` row

### TenantIDPConfigDetailView

`GET /api/v1/tenants/idp/{id}/` — retrieve single config (secret masked)
`PATCH /api/v1/tenants/idp/{id}/` — update config (re-store secret if changed)
`DELETE /api/v1/tenants/idp/{id}/` — soft-delete (set `is_active=False`)

### TenantIDPConfigActivateView

`POST /api/v1/tenants/idp/{id}/activate/`

Validates the IDP is reachable before activating:
- For OIDC: fetch `{issuer}/.well-known/openid-configuration`, verify HTTP 200
- For SAML: fetch `metadata_url`, verify HTTP 200 and valid XML
- For google_oauth: no network check needed (Google is always up)

If validation passes: set `is_active=True` on this config, set `is_active=False` on any
other configs of the same `idp_type` for this tenant (only one active per type per tenant).

Returns `{"status": "activated", "idp_name": "..."}` on success or
`{"status": "validation_failed", "reason": "..."}` on failure.

### Serializer

`TenantIDPConfigSerializer` fields:
- Read: `id`, `tenant_id`, `idp_type`, `idp_name`, `is_active`, `config` (with secret masked),
  `allowed_domains`, `created_at`, `updated_at`
- Write: `tenant_id`, `idp_type`, `idp_name`, `config`, `allowed_domains`
- `client_secret` inside config is write-only: never returned in GET responses

## Reference Files

- `platform/cspm-backend/tenant_management/views.py` — existing tenant CRUD views
- `platform/cspm-backend/user_auth/views/invite.py` — `_current_user()` pattern
- `engines/onboarding/storage/secrets_manager_storage.py` — Secrets Manager pattern

## Acceptance Criteria

- [ ] AC1: `POST /api/v1/tenants/idp/` creates a `TenantIDPConfig` row; `client_secret` is NOT stored in DB, stored in Secrets Manager
- [ ] AC2: `GET /api/v1/tenants/idp/` returns config list with `client_secret` replaced by `"[stored]"` in response
- [ ] AC3: Unauthenticated request to any endpoint returns 401
- [ ] AC4: User in tenant A cannot read or modify configs for tenant B (returns 403)
- [ ] AC5: `POST /api/v1/tenants/idp/{id}/activate/` returns 200 with `status=activated` when IDP is reachable
- [ ] AC6: `POST /api/v1/tenants/idp/{id}/activate/` returns 200 with `status=validation_failed` when IDP URL is unreachable (do not raise 5xx)
- [ ] AC7: SAML config creation triggers SP cert/key generation in Secrets Manager

## Definition of Done

- [ ] Code follows Python standards (type hints, docstrings, 4-space indent)
- [ ] API tested via Django test client with mock Secrets Manager
- [ ] Story accepted by SM before merge
