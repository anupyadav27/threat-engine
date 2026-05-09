"""
Migration 0014: replace ciem:read + ciem:sensitive with cdr:read + cdr:sensitive.

Adds 2 new permissions:
  - cdr:read      — access CDR (Cloud Detection & Response) findings
  - cdr:sensitive — view identity activity data for a resource (CDR tab, analyst+)

Migrates existing role assignments from ciem:* → cdr:*, then deletes old permissions.
"""

import uuid

from django.db import migrations


NEW_PERMISSIONS = {
    "cdr:read": (
        "cdr",
        "read",
        True,
        "Access CDR — Cloud Detection & Response findings",
    ),
    "cdr:sensitive": (
        "cdr",
        "sensitive",
        False,
        "View identity activity and behavioral data for a resource",
    ),
}

REPLACE_MAP = {
    "ciem:read":      "cdr:read",
    "ciem:sensitive": "cdr:sensitive",
}


def migrate_ciem_to_cdr(apps, schema_editor):
    Roles = apps.get_model("user_auth", "Roles")
    Permissions = apps.get_model("user_auth", "Permissions")
    RolePermissions = apps.get_model("user_auth", "RolePermissions")

    # 1. Create new CDR permissions
    for key, (feature, action, tenant_scoped, description) in NEW_PERMISSIONS.items():
        Permissions.objects.get_or_create(
            key=key,
            defaults={
                "id": str(uuid.uuid4()),
                "feature": feature,
                "action": action,
                "tenant_scoped": tenant_scoped,
                "description": description,
            },
        )

    # 2. For each old permission, copy its role assignments to the new permission
    for old_key, new_key in REPLACE_MAP.items():
        try:
            old_perm = Permissions.objects.get(key=old_key)
            new_perm = Permissions.objects.get(key=new_key)
        except Permissions.DoesNotExist:
            continue

        for rp in RolePermissions.objects.filter(permission=old_perm):
            RolePermissions.objects.get_or_create(
                role=rp.role,
                permission=new_perm,
                defaults={"id": str(uuid.uuid4())},
            )

        # 3. Delete old permission (cascades role assignments)
        old_perm.delete()


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0014_invitetokens_group_id"),
    ]

    operations = [
        migrations.RunPython(migrate_ciem_to_cdr, reverse_code=noop_reverse),
    ]
