---
story_id: AUTH-12
title: Migrate existing Okta config to TenantIDPConfig
status: ready
sprint: auth-redesign-2
depends_on: [AUTH-04]
blocks: []
sme: Django/Python backend engineer + DBA
estimate: 0.5 day
---

# Story: Migrate Existing Okta Users to TenantIDPConfig

## Context

Existing users with `sso_provider='okta'` were onboarded via the old static `djangosaml2`
config (env vars: `OKTA_METADATA`, `SAML_AUDIENCE`, `SAML_CALLBACK_URL`).

After AUTH-04 ships, the static config is removed. This story creates:
1. A `TenantIDPConfig` row for the existing Okta IDP, using the env var values
2. Links it to the correct tenant (the auto-provisioned tenant of the first Okta user)

## Files to Create/Modify

- `platform/cspm-backend/user_auth/management/commands/migrate_okta_idp.py` — NEW: management command

## Implementation Notes

```python
# migrate_okta_idp.py
import os
from django.core.management.base import BaseCommand
from tenant_management.models import Tenants, TenantIDPConfig, TenantUsers

class Command(BaseCommand):
    help = "Migrate static Okta SAML config to TenantIDPConfig table"

    def handle(self, *args, **options):
        okta_metadata_url = os.getenv("OKTA_METADATA")
        saml_audience = os.getenv("SAML_AUDIENCE")
        acs_url = os.getenv("SAML_CALLBACK_URL")

        if not okta_metadata_url:
            self.stdout.write("OKTA_METADATA not set — skipping migration")
            return

        # Find tenants that have users with sso_provider='okta'
        from user_auth.models import Users
        okta_users = Users.objects.filter(sso_provider='okta')
        tenant_ids = set(
            TenantUsers.objects.filter(user__in=okta_users)
            .values_list('tenant_id', flat=True)
        )

        for tenant_id in tenant_ids:
            tenant = Tenants.objects.get(id=tenant_id)
            existing = TenantIDPConfig.objects.filter(
                tenant=tenant, idp_type='saml', idp_name='Okta'
            )
            if existing.exists():
                self.stdout.write(f"Tenant {tenant.name}: TenantIDPConfig already exists, skipping")
                continue

            TenantIDPConfig.objects.create(
                tenant=tenant,
                idp_type='saml',
                idp_name='Okta',
                is_active=True,
                config={
                    "entity_id": "okta",  # placeholder; update if known
                    "metadata_url": okta_metadata_url,
                    "sp_entity_id": saml_audience,
                    "acs_url": acs_url,
                    "attribute_mapping": {
                        "email": "uid",
                        "first_name": "firstName",
                        "last_name": "lastName"
                    }
                },
                allowed_domains=[],  # admin should configure post-migration
            )
            self.stdout.write(f"Created TenantIDPConfig for tenant: {tenant.name}")

        self.stdout.write("Migration complete")
```

Run: `python manage.py migrate_okta_idp` in the platform pod after AUTH-04 is deployed.

## Acceptance Criteria

- [ ] AC1: Management command runs without error when `OKTA_METADATA` is set
- [ ] AC2: Creates one `TenantIDPConfig` row per tenant that has Okta users
- [ ] AC3: Does not create duplicate rows if run twice (idempotent)
- [ ] AC4: Command output lists each tenant processed
- [ ] AC5: Existing Okta users can still log in after migration (AUTH-04 fallback → new TenantIDPConfig)

## Definition of Done

- [ ] Command is runnable via `kubectl exec`
- [ ] Story accepted by SM before merge