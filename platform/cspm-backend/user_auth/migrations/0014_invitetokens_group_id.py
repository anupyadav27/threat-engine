"""
Migration: add nullable group_id FK to invite_tokens.

BILL-S06 — admins can optionally assign an invited user to a CsmGroup at invite
creation time. Uses SET_NULL so deleting the group never cascades to outstanding
invites; it simply clears the group assignment.
"""
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0013_ciem_sensitive_permission'),
        ('tenant_management', '0007_tenant_type_customer_id_and_groups'),
    ]

    operations = [
        migrations.AddField(
            model_name='invitetokens',
            name='group',
            field=models.ForeignKey(
                'tenant_management.CsmGroups',
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                db_column='group_id',
                db_index=True,
                related_name='invite_tokens',
            ),
        ),
    ]
