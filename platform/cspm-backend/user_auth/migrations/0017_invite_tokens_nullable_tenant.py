"""
Migration 0017: Make InviteTokens.tenant nullable.

onboarding-D2 introduces a customer_id-scoped invite flow that does not require
a tenant FK (invites are scoped at the org/customer level, not a specific tenant).
Setting null=True, blank=True on the tenant FK allows InviteUserView to create
tokens without a tenant, while preserving all existing tenant-scoped rows.

CASCADE is replaced with SET_NULL so that deleting a tenant never silently
removes outstanding invite tokens — the orphaned tokens simply have tenant=None.
"""
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0016_remove_developer_role"),
        ("tenant_management", "0007_tenant_type_customer_id_and_groups"),
    ]

    operations = [
        migrations.AlterField(
            model_name="invitetokens",
            name="tenant",
            field=models.ForeignKey(
                "tenant_management.Tenants",
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                db_column="tenant_id",
            ),
        ),
    ]
