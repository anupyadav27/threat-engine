"""
Migration 0007: Add tenant_type + customer_id to Tenants; role FK on UserAccountAccess;
create CsmGroups, GroupMembers, TenantGroupAccess, AccountGroupAccess models.

DB is already updated by raw SQL migration 20260503_cspm_cleanup_and_org_foundation.sql.
This migration only updates Django's migration state (SeparateDatabaseAndState).
"""

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("tenant_management", "0006_user_account_access"),
        ("user_auth", "0011_users_customer_id_and_user_admin_scope"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                # tenant_type and customer_id on Tenants
                migrations.AddField(
                    model_name="tenants",
                    name="tenant_type",
                    field=models.CharField(default="cloud", max_length=50),
                ),
                migrations.AddField(
                    model_name="tenants",
                    name="customer_id",
                    field=models.CharField(blank=True, db_index=True, max_length=255, null=True),
                ),
                # role FK on UserAccountAccess
                migrations.AddField(
                    model_name="useraccountaccess",
                    name="role",
                    field=models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="account_access_grants",
                        to="user_auth.roles",
                    ),
                ),
                # Group models
                migrations.CreateModel(
                    name="CsmGroups",
                    fields=[
                        ("id", models.TextField(default=__import__("uuid").uuid4, editable=False, primary_key=True, serialize=False)),
                        ("customer_id", models.CharField(db_index=True, max_length=255)),
                        ("name", models.CharField(max_length=255)),
                        ("description", models.TextField(blank=True, null=True)),
                        ("created_at", models.DateTimeField(auto_now_add=True)),
                        ("updated_at", models.DateTimeField(auto_now=True)),
                        ("created_by", models.ForeignKey(
                            null=True,
                            on_delete=django.db.models.deletion.SET_NULL,
                            related_name="groups_created",
                            to=settings.AUTH_USER_MODEL,
                        )),
                    ],
                    options={
                        "db_table": "csm_groups",
                        "unique_together": {("customer_id", "name")},
                    },
                ),
                migrations.CreateModel(
                    name="GroupMembers",
                    fields=[
                        ("id", models.TextField(default=__import__("uuid").uuid4, editable=False, primary_key=True, serialize=False)),
                        ("added_at", models.DateTimeField(auto_now_add=True)),
                        ("group", models.ForeignKey(
                            on_delete=django.db.models.deletion.CASCADE,
                            related_name="members",
                            to="tenant_management.csmgroups",
                        )),
                        ("user", models.ForeignKey(
                            on_delete=django.db.models.deletion.CASCADE,
                            related_name="group_memberships",
                            to=settings.AUTH_USER_MODEL,
                        )),
                    ],
                    options={
                        "db_table": "group_members",
                        "unique_together": {("group", "user")},
                    },
                ),
                migrations.CreateModel(
                    name="TenantGroupAccess",
                    fields=[
                        ("id", models.TextField(default=__import__("uuid").uuid4, editable=False, primary_key=True, serialize=False)),
                        ("granted_at", models.DateTimeField(auto_now_add=True)),
                        ("group", models.ForeignKey(
                            on_delete=django.db.models.deletion.CASCADE,
                            related_name="tenant_access",
                            to="tenant_management.csmgroups",
                        )),
                        ("tenant", models.ForeignKey(
                            on_delete=django.db.models.deletion.CASCADE,
                            related_name="group_access",
                            to="tenant_management.tenants",
                        )),
                        ("role", models.ForeignKey(
                            on_delete=django.db.models.deletion.PROTECT,
                            related_name="tenant_group_grants",
                            to="user_auth.roles",
                        )),
                    ],
                    options={
                        "db_table": "tenant_group_access",
                        "unique_together": {("group", "tenant")},
                    },
                ),
                migrations.CreateModel(
                    name="AccountGroupAccess",
                    fields=[
                        ("id", models.TextField(default=__import__("uuid").uuid4, editable=False, primary_key=True, serialize=False)),
                        ("account_id", models.CharField(max_length=512)),
                        ("granted_at", models.DateTimeField(auto_now_add=True)),
                        ("group", models.ForeignKey(
                            on_delete=django.db.models.deletion.CASCADE,
                            related_name="account_access",
                            to="tenant_management.csmgroups",
                        )),
                        ("tenant", models.ForeignKey(
                            on_delete=django.db.models.deletion.CASCADE,
                            related_name="account_group_access",
                            to="tenant_management.tenants",
                        )),
                        ("role", models.ForeignKey(
                            on_delete=django.db.models.deletion.PROTECT,
                            related_name="account_group_grants",
                            to="user_auth.roles",
                        )),
                    ],
                    options={
                        "db_table": "account_group_access",
                        "unique_together": {("group", "tenant", "account_id")},
                    },
                ),
            ],
            database_operations=[],
        ),
    ]
