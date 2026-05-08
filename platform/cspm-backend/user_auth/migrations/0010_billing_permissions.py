"""
Migration 0010: seed billing permissions and assign to roles.

Adds 3 new permission keys:
  - billing:read    — view subscription plan, usage, and invoice history
  - billing:write   — upgrade/downgrade/cancel subscription; manage payment methods
  - platform:admin  — full operator access: engine health, org management, billing overrides

Role assignments:
  - org_admin      → billing:read, billing:write
  - tenant_admin   → billing:read
  - platform_admin → billing:read, billing:write, platform:admin
"""

import uuid

from django.db import migrations


# ---------------------------------------------------------------------------
# New permissions to add
# ---------------------------------------------------------------------------

NEW_PERMISSIONS = {
    "billing:read": (
        "billing",
        "read",
        False,
        "View subscription plan, usage, and invoice history",
    ),
    "billing:write": (
        "billing",
        "write",
        False,
        "Upgrade, downgrade, cancel subscription; manage payment methods",
    ),
    "platform:admin": (
        "platform",
        "admin",
        False,
        "Full operator access: engine health, org management, billing overrides",
    ),
}

# Role -> set of new permission keys to assign
NEW_ROLE_PERMISSIONS = {
    "org_admin": {"billing:read", "billing:write"},
    "tenant_admin": {"billing:read"},
    "platform_admin": {"billing:read", "billing:write", "platform:admin"},
}


# ---------------------------------------------------------------------------
# Forward migration
# ---------------------------------------------------------------------------

def add_billing_permissions(apps, schema_editor):
    """Idempotent seed of billing permissions and role assignments.

    Uses get_or_create so re-running this migration produces no duplicate rows.
    """
    Roles = apps.get_model("user_auth", "Roles")
    Permissions = apps.get_model("user_auth", "Permissions")
    RolePermissions = apps.get_model("user_auth", "RolePermissions")

    # 1. Seed permissions
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

    # 2. Seed role_permissions junction rows
    for role_name, perm_keys in NEW_ROLE_PERMISSIONS.items():
        try:
            role = Roles.objects.get(name=role_name)
        except Roles.DoesNotExist:
            # Role not seeded yet — skip gracefully (migration 0009 must run first)
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
    """Reverse is a no-op.

    Removing billing permissions could break live sessions — the caller must
    manually purge permissions_cache from user_sessions if a rollback is needed.
    """
    pass


# ---------------------------------------------------------------------------
# Migration class
# ---------------------------------------------------------------------------

class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0009_seed_roles_permissions"),
    ]

    operations = [
        migrations.RunPython(add_billing_permissions, reverse_code=noop_reverse),
    ]
