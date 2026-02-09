# Generated manually for multi-tenant isolation (user_admin_scope)

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserAdminScope",
            fields=[
                ("id", models.TextField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("scope_type", models.CharField(choices=[("customer", "customer"), ("tenant", "tenant"), ("landlord", "landlord")], max_length=32)),
                ("scope_id", models.CharField(max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("role", models.ForeignKey(blank=True, db_column="role_id", null=True, on_delete=django.db.models.deletion.CASCADE, related_name="admin_scopes", to="user_auth.roles")),
                ("user", models.ForeignKey(db_column="user_id", on_delete=django.db.models.deletion.CASCADE, related_name="admin_scopes", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "db_table": "user_admin_scope",
                "ordering": ["user", "scope_type", "scope_id"],
            },
        ),
    ]
