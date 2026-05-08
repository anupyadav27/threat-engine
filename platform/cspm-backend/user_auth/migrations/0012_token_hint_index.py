"""
Migration 0012: Add db_index=True to UserSessions.token_hint (WARN-01).

The index already exists in the live DB (created by earlier raw migration).
This migration only updates Django's migration state (SeparateDatabaseAndState).
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0011_users_customer_id_and_user_admin_scope"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="usersessions",
                    name="token_hint",
                    field=models.CharField(blank=True, db_index=True, max_length=8, null=True),
                ),
            ],
            database_operations=[],
        ),
    ]
