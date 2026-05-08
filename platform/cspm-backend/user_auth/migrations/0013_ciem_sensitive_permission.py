"""
Migration 0013: seed ciem:sensitive permission and assign to roles.

Adds 1 new permission key:
  - ciem:sensitive — view identity entitlement data for a resource (CIEM tab, analyst+)

Role assignments:
  - analyst      → ciem:sensitive
  - tenant_admin → ciem:sensitive
  - org_admin    → ciem:sensitive
  - platform_admin → ciem:sensitive
  - viewer       → (no grant — 403 on CIEM tab)
"""

import uuid

from django.db import migrations


NEW_PERMISSIONS = {
    "ciem:sensitive": (
        "ciem",
        "sensitive",
        False,
        "View identity entitlement data for a resource",
    ),
}

NEW_ROLE_PERMISSIONS = {
    "analyst": {"ciem:sensitive"},
    "tenant_admin": {"ciem:sensitive"},
    "org_admin": {"ciem:sensitive"},
    "platform_admin": {"ciem:sensitive"},
}


def add_ciem_sensitive_permission(apps, schema_editor):
    Roles = apps.get_model("user_auth", "Roles")
    Permissions = apps.get_model("user_auth", "Permissions")
    RolePermissions = apps.get_model("user_auth", "RolePermissions")

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

    for role_name, perm_keys in NEW_ROLE_PERMISSIONS.items():
        try:
            role = Roles.objects.get(name=role_name)
        except Roles.DoesNotExist:
            continue
        for key in perm_keys:
            try:
                perm = Permissions.objects.get(key=key)
            except Permissions.DoesNotExist:
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
        ("user_auth", "0012_token_hint_index"),
    ]

    operations = [
        migrations.RunPython(add_ciem_sensitive_permission, reverse_code=noop_reverse),
    ]
