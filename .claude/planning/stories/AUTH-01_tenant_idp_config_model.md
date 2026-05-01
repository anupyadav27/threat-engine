---
story_id: AUTH-01
title: TenantIDPConfig model + migration
status: ready
sprint: auth-redesign-1
depends_on: []
blocks: [AUTH-02, AUTH-03, AUTH-04, AUTH-05]
sme: Django/Python backend engineer
estimate: 0.5 day
---

# Story: TenantIDPConfig Model + Migration

## Context

The platform currently stores all IDP configuration as static env vars in `settings.py`
(single Okta SAML config, single Google OAuth config). This prevents any tenant from
using their own IDP. The `tenant_management.Tenants` model has no IDP config field.

This story introduces the `TenantIDPConfig` Django model that stores per-tenant IDP
settings, enabling subsequent stories (AUTH-02 through AUTH-05) to read tenant-specific
IDP config at auth time.

## Files to Create/Modify

- `platform/cspm-backend/tenant_management/models.py` — add `TenantIDPConfig` model
- `platform/cspm-backend/tenant_management/migrations/0004_tenantidpconfig.py` — new migration
- `platform/cspm-backend/tenant_management/serializers.py` — add `TenantIDPConfigSerializer`

## Implementation Notes

### Model Definition

Add to `platform/cspm-backend/tenant_management/models.py`:

```python
class TenantIDPConfig(models.Model):
    IDP_TYPE_CHOICES = [
        ('google_oauth', 'Google OAuth'),
        ('oidc', 'Generic OIDC'),
        ('saml', 'SAML 2.0'),
    ]

    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name='idp_configs'
    )
    idp_type = models.CharField(max_length=20, choices=IDP_TYPE_CHOICES)
    idp_name = models.CharField(max_length=255)  # display name, e.g. "Acme Okta"
    is_active = models.BooleanField(default=False)
    config = models.JSONField()  # IDP-type-specific config — see notes below
    allowed_domains = models.JSONField(default=list)  # ["acme.com", "acme.org"]
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='idp_configs_created'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'tenant_idp_configs'
        unique_together = ('tenant', 'idp_type', 'idp_name')
        indexes = [
            models.Index(fields=['tenant', 'idp_type', 'is_active']),
        ]
```

### Config JSONB schemas (document in model docstring)

**google_oauth**:
```json
{
  "client_id": "xxx.apps.googleusercontent.com",
  "client_secret_ref": "platform/idp/{tenant_id}/google",
  "allowed_hd": ["acme.com"]
}
```

**oidc**:
```json
{
  "issuer": "https://acme.okta.com/oauth2/default",
  "client_id": "...",
  "client_secret_ref": "platform/idp/{tenant_id}/oidc",
  "scopes": ["openid", "email", "profile"],
  "claims_mapping": {"email": "email", "first_name": "given_name", "last_name": "family_name"},
  "pkce": true
}
```

**saml**:
```json
{
  "entity_id": "https://acme.okta.com/app/.../sso/saml",
  "metadata_url": "https://acme.okta.com/app/.../sso/saml/metadata",
  "metadata_xml": null,
  "attribute_mapping": {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "first_name": "firstName",
    "last_name": "lastName"
  },
  "sp_entity_id": "https://cspm.platform/saml/{tenant_id}/sp",
  "acs_url": "https://cspm.platform/api/auth/saml/{tenant_id}/acs/"
}
```

### Serializer

Add `TenantIDPConfigSerializer` to `serializers.py`. Exclude `config.client_secret_ref`
from read responses (write-only field). The serializer should validate that `config`
contains required keys for the given `idp_type`.

### Migration

Run `python manage.py makemigrations tenant_management` after adding the model.
Ensure migration does NOT depend on user_auth migrations beyond 0006 (current max).

## Reference Files

- `platform/cspm-backend/tenant_management/models.py` — existing Tenants model to extend
- `platform/cspm-backend/tenant_management/migrations/0003_alter_tenants_options_alter_tenantusers_options_and_more.py` — latest migration to base off

## Acceptance Criteria

- [ ] AC1: `python manage.py migrate` runs without error on a clean DB
- [ ] AC2: `TenantIDPConfig` table exists in DB with columns: `id`, `tenant_id`, `idp_type`, `idp_name`, `is_active`, `config` (JSONB), `allowed_domains` (JSONB array), `created_by_id`, `created_at`, `updated_at`
- [ ] AC3: Unique constraint enforced: cannot create two `TenantIDPConfig` rows with same `(tenant_id, idp_type, idp_name)`
- [ ] AC4: Composite index on `(tenant_id, idp_type, is_active)` exists
- [ ] AC5: `TenantIDPConfigSerializer` excludes `client_secret_ref` from GET responses

## Definition of Done

- [ ] Code follows project Python standards (type hints, Google-style docstrings, 4-space indent)
- [ ] Migration file committed alongside model change
- [ ] No existing migrations broken (`makemigrations --check` returns 0)
- [ ] Story accepted by SM before merge
