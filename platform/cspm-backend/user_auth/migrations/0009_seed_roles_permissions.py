import uuid

from django.db import migrations


# ---------------------------------------------------------------------------
# Seed data constants
# ---------------------------------------------------------------------------

ROLES = [
    dict(
        name='platform_admin',
        level=1,
        scope_level='platform',
        tenant_scoped=False,
        description='Full platform access across all organizations and tenants',
    ),
    dict(
        name='org_admin',
        level=2,
        scope_level='organization',
        tenant_scoped=False,
        description='Organization-wide admin across all tenants in org',
    ),
    dict(
        name='tenant_admin',
        level=4,
        scope_level='tenant',
        tenant_scoped=True,
        description='Full admin within a single tenant',
    ),
    dict(
        name='analyst',
        level=4,
        scope_level='tenant',
        tenant_scoped=True,
        description='Read + scan access within a tenant; no user management',
    ),
    dict(
        name='viewer',
        level=4,
        scope_level='tenant',
        tenant_scoped=True,
        description='Read-only access to core findings; no sensitive data endpoints',
    ),
]

# key -> (feature, action, tenant_scoped)
# tenant_scoped=False for cross-tenant administrative permissions
PERMISSIONS = {
    'discoveries:read':    ('discoveries',   'read',      True),
    'check:read':          ('check',         'read',      True),
    'threat:read':         ('threat',        'read',      True),
    'inventory:read':      ('inventory',     'read',      True),
    'compliance:read':     ('compliance',    'read',      True),
    'iam:read':            ('iam',           'read',      True),
    'ciem:read':           ('ciem',          'read',      True),
    'network:read':        ('network',       'read',      True),
    'risk:read':           ('risk',          'read',      True),
    'datasec:read':        ('datasec',       'read',      True),
    'datasec:sensitive':   ('datasec',       'sensitive', True),
    'secops:read':         ('secops',        'read',      True),
    'vulnerability:read':  ('vulnerability', 'read',      True),
    'scans:create':        ('scans',         'create',    True),
    'scans:delete':        ('scans',         'delete',    True),
    'users:read':          ('users',         'read',      True),
    'users:write':         ('users',         'write',     False),
    'rules:read':          ('rules',         'read',      True),
    'rules:write':         ('rules',         'write',     False),
    'tenants:read':        ('tenants',       'read',      False),
    'tenants:write':       ('tenants',       'write',     False),
    'settings:read':       ('settings',      'read',      True),
    'settings:write':      ('settings',      'write',     False),
    # Enterprise engine permissions
    'ai_security:read':    ('ai_security',   'read',      True),
    'encryption:read':     ('encryption',    'read',      True),
    'dbsec:read':          ('dbsec',         'read',      True),
    'container:read':      ('container',     'read',      True),
}

# Role -> set of permission keys
ROLE_PERMISSIONS = {
    'platform_admin': {
        'discoveries:read', 'check:read', 'threat:read', 'inventory:read',
        'compliance:read', 'iam:read', 'ciem:read', 'network:read', 'risk:read',
        'datasec:read', 'datasec:sensitive', 'secops:read', 'vulnerability:read',
        'ai_security:read', 'encryption:read', 'dbsec:read', 'container:read',
        'scans:create', 'scans:delete',
        'users:read', 'users:write',
        'rules:read', 'rules:write',
        'tenants:read', 'tenants:write',
        'settings:read', 'settings:write',
    },
    'org_admin': {
        'discoveries:read', 'check:read', 'threat:read', 'inventory:read',
        'compliance:read', 'iam:read', 'ciem:read', 'network:read', 'risk:read',
        'datasec:read', 'datasec:sensitive', 'secops:read', 'vulnerability:read',
        'ai_security:read', 'encryption:read', 'dbsec:read', 'container:read',
        'scans:create', 'scans:delete',
        'users:read', 'users:write',
        'rules:read', 'rules:write',
        'tenants:read',
        'settings:read', 'settings:write',
    },
    'tenant_admin': {
        'discoveries:read', 'check:read', 'threat:read', 'inventory:read',
        'compliance:read', 'iam:read', 'ciem:read', 'network:read', 'risk:read',
        'datasec:read', 'datasec:sensitive', 'secops:read', 'vulnerability:read',
        'ai_security:read', 'encryption:read', 'dbsec:read', 'container:read',
        'scans:create',
        'users:read', 'users:write',
        'rules:read',
        'settings:read', 'settings:write',
    },
    'analyst': {
        'discoveries:read', 'check:read', 'threat:read', 'inventory:read',
        'compliance:read', 'iam:read', 'ciem:read', 'network:read', 'risk:read',
        'datasec:read', 'datasec:sensitive', 'secops:read', 'vulnerability:read',
        'ai_security:read', 'encryption:read', 'dbsec:read', 'container:read',
        'rules:read',
    },
    'viewer': {
        'discoveries:read', 'check:read', 'threat:read', 'inventory:read',
        'compliance:read', 'iam:read', 'ciem:read', 'network:read', 'risk:read',
    },
}


# ---------------------------------------------------------------------------
# Forward migration: seed roles, permissions, role_permissions
# ---------------------------------------------------------------------------

def seed_roles_permissions(apps, schema_editor):
    """Idempotent seed of standard RBAC roles, permission keys, and matrix.

    Uses get_or_create throughout so re-running this migration produces no
    duplicate rows.  The platform_admin role is seeded but assigned to zero
    users — user assignment is a separate admin action.
    """
    Roles = apps.get_model('user_auth', 'Roles')
    Permissions = apps.get_model('user_auth', 'Permissions')
    RolePermissions = apps.get_model('user_auth', 'RolePermissions')

    # 1. Seed roles
    for role_data in ROLES:
        Roles.objects.get_or_create(
            name=role_data['name'],
            defaults={
                'id': str(uuid.uuid4()),
                'level': role_data['level'],
                'scope_level': role_data['scope_level'],
                'tenant_scoped': role_data['tenant_scoped'],
                'description': role_data['description'],
            },
        )

    # 2. Seed permissions
    for key, (feature, action, tenant_scoped) in PERMISSIONS.items():
        Permissions.objects.get_or_create(
            key=key,
            defaults={
                'id': str(uuid.uuid4()),
                'feature': feature,
                'action': action,
                'tenant_scoped': tenant_scoped,
            },
        )

    # 3. Seed role_permissions junction rows
    for role_name, perm_keys in ROLE_PERMISSIONS.items():
        role = Roles.objects.get(name=role_name)
        for key in perm_keys:
            perm = Permissions.objects.get(key=key)
            RolePermissions.objects.get_or_create(
                role=role,
                permission=perm,
                defaults={'id': str(uuid.uuid4())},
            )


def noop_reverse(apps, schema_editor):
    """Reverse is a no-op.

    Seeded roles are structural data — removing them in a reverse migration
    could cascade-delete user_roles rows and break live tenants.
    """
    pass


# ---------------------------------------------------------------------------
# Migration class
# ---------------------------------------------------------------------------

class Migration(migrations.Migration):

    dependencies = [
        ('user_auth', '0008_roles_level_sessions_cache'),
    ]

    operations = [
        migrations.RunPython(seed_roles_permissions, reverse_code=noop_reverse),
    ]
