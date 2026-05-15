"""Migration 0016: Remove the 'developer' role (BLOCK-07 / auth-B4).

The 'developer' convenience role bypassed all RBAC checks and must be
eliminated before production hardening.  This migration:

  1. Finds any users assigned the 'developer' role.
  2. Re-assigns those users to 'org_admin' (the closest production-equivalent).
  3. Deletes all role_permissions rows for 'developer'.
  4. Deletes the 'developer' role itself.

The migration is fully idempotent — if the 'developer' role has already been
removed, it exits silently without error.

Affected users (if any) will be listed in the Django migration log output.
Post-deploy manual step (run AFTER B4 confirmed working):
  INSERT INTO role_permissions (id, role_id, permission_id, created_at, updated_at)
  SELECT gen_random_uuid()::text, r.id, p.id, NOW(), NOW()
  FROM roles r, permissions p
  WHERE r.name = 'org_admin' AND p.key IN ('orgs:write', 'users:write')
  ON CONFLICT DO NOTHING;
"""

import logging

from django.db import migrations

logger = logging.getLogger(__name__)


def remove_developer_role(apps, schema_editor):
    Roles = apps.get_model("user_auth", "Roles")
    UserRoles = apps.get_model("user_auth", "UserRoles")
    RolePermissions = apps.get_model("user_auth", "RolePermissions")

    try:
        dev_role = Roles.objects.get(name="developer")
    except Roles.DoesNotExist:
        logger.info("0016_remove_developer_role: 'developer' role not found — nothing to do.")
        return

    # Identify affected users before reassignment for audit trail
    affected = list(
        UserRoles.objects.filter(role=dev_role).values_list("user_id", flat=True)
    )
    if affected:
        logger.warning(
            "0016_remove_developer_role: migrating %d user(s) from 'developer' "
            "to 'org_admin': %s",
            len(affected),
            affected,
        )

    try:
        org_admin_role = Roles.objects.get(name="org_admin")
    except Roles.DoesNotExist:
        logger.error(
            "0016_remove_developer_role: 'org_admin' role not found — "
            "cannot reassign developer users; deleting developer role anyway."
        )
        org_admin_role = None

    if org_admin_role and affected:
        for user_id in affected:
            # get_or_create avoids duplicate-key errors if user already has org_admin
            UserRoles.objects.get_or_create(
                user_id=user_id,
                role=org_admin_role,
            )

    # Remove developer role assignments and the role itself
    UserRoles.objects.filter(role=dev_role).delete()
    RolePermissions.objects.filter(role=dev_role).delete()
    dev_role.delete()

    logger.info(
        "0016_remove_developer_role: 'developer' role deleted; "
        "%d user(s) reassigned to 'org_admin'.",
        len(affected),
    )


def noop_reverse(apps, schema_editor):
    # The developer role is intentionally not recreated on rollback.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("user_auth", "0015_cdr_permissions"),
    ]

    operations = [
        migrations.RunPython(remove_developer_role, reverse_code=noop_reverse),
    ]
