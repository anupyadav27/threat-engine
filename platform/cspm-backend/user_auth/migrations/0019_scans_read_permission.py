"""
Migration 0019: add scans:read permission.

The onboarding engine's /api/v1/scans/recent and /api/v1/scans/history
endpoints use require_permission("scans:read"). The seed migration (0009)
only created scans:create and scans:delete, so authenticated requests from
analyst and above were returning 403.

Granted to: analyst, tenant_admin, org_admin, platform_admin.
viewer is excluded — scan history is operational data, not a read-only
posture view.
"""

import uuid

from django.db import migrations


ROLES_WITH_SCANS_READ = [
    "analyst",
    "tenant_admin",
    "org_admin",
    "platform_admin",
]


def add_scans_read(apps, schema_editor):
    Roles = apps.get_model("user_auth", "Roles")
    Permissions = apps.get_model("user_auth", "Permissions")
    RolePermissions = apps.get_model("user_auth", "RolePermissions")

    perm, _ = Permissions.objects.get_or_create(
        key="scans:read",
        defaults={
            "id": str(uuid.uuid4()),
            "feature": "scans",
            "action": "read",
            "tenant_scoped": True,
        },
    )

    for role_name in ROLES_WITH_SCANS_READ:
        try:
            role = Roles.objects.get(name=role_name)
        except Roles.DoesNotExist:
            continue
        RolePermissions.objects.get_or_create(
            role=role,
            permission=perm,
            defaults={"id": str(uuid.uuid4())},
        )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0018_attack_path_permissions"),
    ]

    operations = [
        migrations.RunPython(add_scans_read, reverse_code=noop_reverse),
    ]
