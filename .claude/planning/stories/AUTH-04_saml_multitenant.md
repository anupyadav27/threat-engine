---
story_id: AUTH-04
title: SAML 2.0 multi-tenant (python3-saml, replaces djangosaml2)
status: ready
sprint: auth-redesign-1
depends_on: [AUTH-01]
blocks: [AUTH-08, AUTH-12]
sme: Django/Python backend engineer with SAML experience
estimate: 2 days
---

# Story: SAML 2.0 Multi-Tenant Support

## Context

The current SAML implementation uses `djangosaml2` with a single static `SAML_CONFIG` in
`settings.py`, hardcoded to Okta via `OKTA_METADATA` env var. `saml_auth.py` hardcodes
`sso_provider='okta'`. This makes it impossible for any other tenant to use SAML or for
any SAML IDP other than Okta to work.

This story replaces `djangosaml2` views with `python3-saml` (OneLogin library), which
accepts configuration per-request enabling true multi-tenant SAML.

## Files to Create/Modify

- `platform/cspm-backend/user_auth/views/saml_auth.py` — full rewrite
- `platform/cspm-backend/user_auth/urls.py` — replace djangosaml2 routes with new per-tenant routes
- `platform/cspm-backend/config/settings.py` — remove SAML_CONFIG, keep SAML_DJANGO_USER_MAIN_ATTRIBUTE if needed
- `platform/cspm-backend/requirements.txt` — add `python3-saml>=1.16.0`, remove `djangosaml2`
- `platform/cspm-backend/user_auth/utils/saml_utils.py` — NEW: SP cert/key generation helper

## Implementation Notes

### Install python3-saml

```
python3-saml>=1.16.0
lxml>=5.0.0         # required by python3-saml
xmlsec>=1.3.13      # required by python3-saml (replaces separate xmlsec binary)
```

Remove from `requirements.txt`: `djangosaml2`, `pysaml2`

Remove from `settings.py`: entire `SAML_CONFIG` block, `AUTHENTICATION_BACKENDS` Saml2Backend,
`djangosaml2` from `INSTALLED_APPS`, `djangosaml2.middleware.SessionMiddleware`,
`djangosaml2.middleware.SamlSessionMiddleware`.

### New URL Routes

Replace existing SAML routes in `user_auth/urls.py`:

```python
# Per-tenant SAML routes
path("saml/<str:tenant_id>/login/", SAMLLoginView.as_view(), name="saml_login"),
path("saml/<str:tenant_id>/acs/", SAMLACSView.as_view(), name="saml_acs"),
path("saml/<str:tenant_id>/metadata/", SAMLMetadataView.as_view(), name="saml_metadata"),
path("saml/<str:tenant_id>/logout/", SAMLLogoutView.as_view(), name="saml_logout"),
```

### SAMLLoginView

`GET /api/auth/saml/{tenant_id}/login/`

1. Load `TenantIDPConfig` for `tenant_id` where `idp_type='saml'` and `is_active=True`
2. Load SP cert and key from Secrets Manager: `platform/idp/{tenant_id}/saml_sp_cert`, `platform/idp/{tenant_id}/saml_sp_key`
3. Build `python3-saml` settings dict from config (see structure below)
4. `auth = OneLogin_Saml2_Auth(prepare_django_request(request), saml_settings)`
5. `return HttpResponseRedirect(auth.login())`

### SAMLACSView

`POST /api/auth/saml/{tenant_id}/acs/`

1. Load `TenantIDPConfig` as above
2. `auth = OneLogin_Saml2_Auth(prepare_django_request(request), saml_settings)`
3. `auth.process_response()`
4. If `auth.get_errors()`: return 400 with error list
5. Extract email from `auth.get_nameid()` or attribute mapped via `config.attribute_mapping.email`
6. Upsert `Users` record: `sso_provider='saml'`, `sso_id=email`
7. If new user: call `provision_first_tenant(user)`
8. Create `UserSessions` with `login_method=f"saml:{config.idp_name}"`
9. Set httponly cookies, redirect to dashboard

### SAMLMetadataView

`GET /api/auth/saml/{tenant_id}/metadata/`

Returns SP XML metadata for this tenant. Tenant admin gives this URL to their IDP admin
to configure the SAML app.

### python3-saml settings dict structure

```python
def build_saml_settings(config: dict, sp_cert: str, sp_key: str) -> dict:
    return {
        "strict": True,
        "debug": settings.DEBUG,
        "sp": {
            "entityId": config["sp_entity_id"],
            "assertionConsumerService": {
                "url": config["acs_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "x509cert": sp_cert,
            "privateKey": sp_key,
        },
        "idp": {
            "entityId": config["entity_id"],
            "singleSignOnService": {
                "url": config.get("sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": config.get("idp_x509cert", ""),  # populated from metadata_url fetch
        }
    }
```

### SP Cert/Key Generation (saml_utils.py)

Called at `TenantIDPConfig` creation time for SAML IDPs:

```python
from OpenSSL import crypto

def generate_sp_keypair(tenant_id: str) -> tuple[str, str]:
    """Generate and store SP cert/key in Secrets Manager. Returns (cert_pem, key_pem)."""
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = f"cspm-sp-{tenant_id}"
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode()
    # Store in Secrets Manager
    _store_secret(f"platform/idp/{tenant_id}/saml_sp_cert", cert_pem)
    _store_secret(f"platform/idp/{tenant_id}/saml_sp_key", key_pem)
    return cert_pem, key_pem
```

### IDP Metadata Fetch

When `TenantIDPConfig` is created with `metadata_url`, fetch and parse the XML to
populate `config.idp_x509cert` and `config.sso_url`. Store parsed values back in config JSONB.
This avoids runtime metadata fetches on every login.

### Migration of Existing Okta Users

Existing `Users` rows with `sso_provider='okta'` are valid. AUTH-12 (sprint 2) creates a
`TenantIDPConfig` row for the existing Okta config using current env vars. This story does
NOT break existing Okta users as long as `settings.OKTA_METADATA` env var is still set.
Add a compatibility shim: if tenant has no `TenantIDPConfig` for SAML, check for env-var-based
Okta config and use it as fallback.

## Reference Files

- `platform/cspm-backend/user_auth/views/saml_auth.py` — current implementation (to be replaced)
- `platform/cspm-backend/config/settings.py` — SAML_CONFIG to remove
- `engines/onboarding/storage/secrets_manager_storage.py` — Secrets Manager pattern

## Acceptance Criteria

- [ ] AC1: `GET /api/auth/saml/{valid_tenant_id}/login/` returns 302 to IDP SSO URL
- [ ] AC2: `GET /api/auth/saml/{invalid_tenant_id}/login/` returns 404 JSON
- [ ] AC3: ACS POST with valid SAML response creates `UserSessions` row with `login_method` containing `'saml:'` prefix
- [ ] AC4: ACS POST with invalid SAML assertion returns 400 with error details
- [ ] AC5: `GET /api/auth/saml/{tenant_id}/metadata/` returns valid SP XML metadata
- [x] AC6: SKIPPED — Okta not used in this deployment (user decision). AUTH-12 (sprint 2) seeds TenantIDPConfig rows for any future SAML IDP migration.
- [ ] AC7: `djangosaml2` is removed from `INSTALLED_APPS` and `requirements.txt`
- [ ] AC8: SP cert/key for new SAML configs is stored in Secrets Manager, not on disk

## Definition of Done

- [ ] Code follows Python standards (type hints, docstrings, 4-space indent)
- [ ] `python3-saml` added to `requirements.txt`, `djangosaml2` removed
- [ ] Tested against at least one real SAML IDP (Okta dev account)
- [ ] Existing Okta integration does not regress
- [ ] Story accepted by SM before merge
