"""
Migration 0020: add cloud_accounts:write permission.

The onboarding engine's create/update/delete/credentials endpoints all use
require_permission("cloud_accounts:write"). Migration 0009 only seeded
cloud_accounts:read, so all wizard mutation operations (create account,
PATCH provider, store credentials, issue agent token) were returning 403
for every role including platform_admin.

Granted to: platform_admin, org_admin, tenant_admin, analyst.
viewer excluded — account creation is an admin/operator action.
"""

import uuid

from django.db import migrations


ROLES_WITH_CLOUD_ACCOUNTS_WRITE = [
    "platform_admin",
    "org_admin",
    "tenant_admin",
    "analyst",
]


def add_cloud_accounts_write(apps, schema_editor):
    Roles = apps.get_model("user_auth", "Roles")
    Permissions = apps.get_model("user_auth", "Permissions")
    RolePermissions = apps.get_model("user_auth", "RolePermissions")

    perm, _ = Permissions.objects.get_or_create(
        key="cloud_accounts:write",
        defaults={
            "id": str(uuid.uuid4()),
            "feature": "cloud_accounts",
            "action": "write",
            "tenant_scoped": True,
        },
    )

    for role_name in ROLES_WITH_CLOUD_ACCOUNTS_WRITE:
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
        ("user_auth", "0019_scans_read_permission"),
    ]

    operations = [
        migrations.RunPython(add_cloud_accounts_write, reverse_code=noop_reverse),
    ]
