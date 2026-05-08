"""
Migration 0011: Add customer_id to Users; create UserAdminScope model.

DB is already updated by raw SQL migration 20260503_cspm_cleanup_and_org_foundation.sql.
This migration only updates Django's migration state (SeparateDatabaseAndState).
"""

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0010_billing_permissions"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AddField(
                    model_name="users",
                    name="customer_id",
                    field=models.CharField(blank=True, db_index=True, max_length=255, null=True),
                ),
                migrations.CreateModel(
                    name="UserAdminScope",
                    fields=[
                        ("id", models.TextField(default=__import__("uuid").uuid4, editable=False, primary_key=True, serialize=False)),
                        ("scope_type", models.CharField(max_length=50)),
                        ("scope_id", models.CharField(max_length=255)),
                        ("created_at", models.DateTimeField(auto_now_add=True)),
                        ("updated_at", models.DateTimeField(auto_now=True)),
                        ("role", models.ForeignKey(
                            blank=True,
                            null=True,
                            on_delete=django.db.models.deletion.SET_NULL,
                            to="user_auth.roles",
                        )),
                        ("user", models.ForeignKey(
                            on_delete=django.db.models.deletion.CASCADE,
                            related_name="admin_scopes",
                            to=settings.AUTH_USER_MODEL,
                        )),
                    ],
                    options={
                        "db_table": "user_admin_scope",
                    },
                ),
                migrations.AddIndex(
                    model_name="useradminscope",
                    index=models.Index(fields=["user", "scope_type"], name="user_admin_scope_user_type_idx"),
                ),
                migrations.AddIndex(
                    model_name="useradminscope",
                    index=models.Index(fields=["scope_type", "scope_id"], name="user_admin_scope_type_id_idx"),
                ),
            ],
            database_operations=[],
        ),
    ]
