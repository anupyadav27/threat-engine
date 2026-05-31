"""
Migration 0018: Add attack_path:read and attack_path:write permissions.

Permissions added:
  - attack_path:read   — view attack paths and crown jewels (all 5 roles)
  - attack_path:write  — manually override crown jewel classification
                          (platform_admin, org_admin, tenant_admin only)

RBAC matrix:
  Role              attack_path:read   attack_path:write
  platform_admin    YES                YES
  org_admin         YES                YES
  tenant_admin      YES                YES
  analyst           YES                NO
  viewer            YES                NO
"""

import uuid

from django.db import migrations


NEW_PERMISSIONS = {
    "attack_path:read": {
        "feature": "attack_path",
        "action": "read",
        "tenant_scoped": True,
        "description": "View attack paths, crown jewels, and choke points",
    },
    "attack_path:write": {
        "feature": "attack_path",
        "action": "write",
        "tenant_scoped": True,
        "description": "Manually override crown jewel classification",
    },
}

# attack_path:read — all 5 roles
READ_ROLES = {
    "platform_admin",
    "org_admin",
    "tenant_admin",
    "analyst",
    "viewer",
}

# attack_path:write — admin roles only (analyst and viewer do NOT get write)
WRITE_ROLES = {
    "platform_admin",
    "org_admin",
    "tenant_admin",
}


def add_attack_path_permissions(apps, schema_editor):
    Roles = apps.get_model("user_auth", "Roles")
    Permissions = apps.get_model("user_auth", "Permissions")
    RolePermissions = apps.get_model("user_auth", "RolePermissions")

    # Create permissions
    for key, attrs in NEW_PERMISSIONS.items():
        Permissions.objects.get_or_create(
            key=key,
            defaults={
                "id": str(uuid.uuid4()),
                **attrs,
            },
        )

    # Assign read permission to all 5 roles
    read_perm = Permissions.objects.get(key="attack_path:read")
    for role_name in READ_ROLES:
        try:
            role = Roles.objects.get(name=role_name)
            RolePermissions.objects.get_or_create(
                role=role,
                permission=read_perm,
                defaults={"id": str(uuid.uuid4())},
            )
        except Roles.DoesNotExist:
            pass  # Role not seeded yet — skip gracefully

    # Assign write permission to admin roles only
    write_perm = Permissions.objects.get(key="attack_path:write")
    for role_name in WRITE_ROLES:
        try:
            role = Roles.objects.get(name=role_name)
            RolePermissions.objects.get_or_create(
                role=role,
                permission=write_perm,
                defaults={"id": str(uuid.uuid4())},
            )
        except Roles.DoesNotExist:
            pass


def remove_attack_path_permissions(apps, schema_editor):
    Permissions = apps.get_model("user_auth", "Permissions")
    for key in NEW_PERMISSIONS:
        Permissions.objects.filter(key=key).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0017_invite_tokens_nullable_tenant"),
    ]

    operations = [
        migrations.RunPython(
            add_attack_path_permissions,
            reverse_code=remove_attack_path_permissions,
        ),
    ]
