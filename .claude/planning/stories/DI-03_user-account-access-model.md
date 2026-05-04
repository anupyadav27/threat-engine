# DI-03: Django — UserAccountAccess Model + Migration

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P1 — enables account-level scoping in DI-04

## Story
As a platform admin, I need a `UserAccountAccess` model that records which cloud accounts a user is explicitly granted access to, so that `AuthContext.account_ids` can be populated at login and BFF queries can filter data to only the user's accessible accounts.

## Background

`AuthContext.account_ids` exists in the dataclass and is documented as "None = unrestricted". It is never populated today — `compute_auth_caches` always sets `"account_ids": None`. This means every user implicitly sees all accounts in their tenant, with no ability to restrict a junior analyst to only specific AWS accounts.

The Django hierarchy is: Platform → Org → Tenant → Cloud Account. We need the Tenant → Cloud Account link at the user level.

## Files to Modify

1. `/Users/apple/Desktop/threat-engine/platform/cspm-backend/tenant_management/models.py`
2. New migration: `/Users/apple/Desktop/threat-engine/platform/cspm-backend/tenant_management/migrations/0006_user_account_access.py`
3. `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/utils/auth_utils.py` (compute_auth_caches update)

## Change 1: New Model in tenant_management/models.py

Add after the `TenantUsers` model:

```python
class UserAccountAccess(models.Model):
    """
    Explicit account-level access grant for a user within a tenant.

    When this table has rows for a user, AuthContext.account_ids is populated
    with only those account_ids, restricting engine queries.
    When no rows exist for a user, account_ids = None (unrestricted within tenant).

    account_id: Cloud provider account ID (e.g. "588989875114" for AWS,
                subscription UUID for Azure, project ID for GCP).
    """
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='account_access',
    )
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name='account_access',
    )
    account_id = models.CharField(max_length=512)
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='account_grants_given',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_account_access'
        unique_together = ('user', 'tenant', 'account_id')
        indexes = [
            models.Index(fields=['user', 'tenant']),
        ]

    def __str__(self):
        return f"{self.user.email} → {self.tenant.name} → {self.account_id}"
```

## Change 2: Migration file content

```python
from django.db import migrations, models
import django.db.models.deletion
import uuid

class Migration(migrations.Migration):
    dependencies = [
        ('tenant_management', '0005_tenants_engine_tenant_id'),
        ('user_auth', '0010_billing_permissions'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserAccountAccess',
            fields=[
                ('id', models.TextField(primary_key=True, default=uuid.uuid4, editable=False)),
                ('account_id', models.CharField(max_length=512)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('granted_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='account_grants_given',
                    to='user_auth.users',
                )),
                ('tenant', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='account_access',
                    to='tenant_management.tenants',
                )),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='account_access',
                    to='user_auth.users',
                )),
            ],
            options={'db_table': 'user_account_access'},
        ),
        migrations.AddConstraint(
            model_name='useraccountaccess',
            constraint=models.UniqueConstraint(
                fields=['user', 'tenant', 'account_id'],
                name='unique_user_tenant_account',
            ),
        ),
        migrations.AddIndex(
            model_name='useraccountaccess',
            index=models.Index(fields=['user', 'tenant'], name='uaa_user_tenant_idx'),
        ),
    ]
```

## Change 3: compute_auth_caches in auth_utils.py

After the scope_cache block from DI-02, add account_ids resolution:

```python
# Resolve account_ids: None = unrestricted (default), list = explicit grants
from tenant_management.models import UserAccountAccess
account_grants = list(
    UserAccountAccess.objects.filter(user=user)
    .values_list("account_id", flat=True)
)
scope_cache["account_ids"] = account_grants if account_grants else None
```

## Acceptance Criteria

- [ ] Migration runs cleanly: `python manage.py migrate tenant_management 0006_user_account_access`
- [ ] `user_account_access` table created in platform DB with correct columns + constraints
- [ ] `UserAccountAccess.objects.create(user=u, tenant=t, account_id="588989875114")` works
- [ ] `compute_auth_caches` populates `scope_cache["account_ids"]` as non-empty list when grants exist
- [ ] `compute_auth_caches` sets `scope_cache["account_ids"] = None` when no grants exist (unrestricted)
- [ ] Platform admin path unchanged (`account_ids = None`)
- [ ] No impact on existing sessions until re-login

## Security Notes
- Empty grant table = unrestricted (not deny-all). Adding a grant restricts, not grants access.
- `granted_by` FK provides audit trail for who assigned account access.
- No API endpoint in this story — model only. API for managing grants is deferred (not blocking v1).

## Definition of Done
- Migration applied to staging DB
- Manual test: insert a grant row, trigger re-login, inspect scope_cache in user_sessions via psql
